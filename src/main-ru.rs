use std::{
    fs::{self, File},
    io::Read,
    path::Path,
    time::Instant,
};
use rayon::prelude::*;
use zeroize::Zeroize;
use secrecy::{SecretBox, ExposeSecret};
use rand::Rng;

// ====================
// Реализация ChaCha-VR
// ====================

#[derive(Debug)]
pub struct ChaChaVR {
    rounds: u32,         // Количество раундов (четное, >=2)
    state: [u32; 16],    // Внутреннее состояние (16 x 32-битных слов)
    keystream: [u8; 64], // 64-байтовый блок ключевого потока
    pos: usize,          // Текущая позиция в кейстрииме (0..63)
}

impl Drop for ChaChaVR {
    fn drop(&mut self) {
        self.state.zeroize();
        self.keystream.zeroize();
        self.pos.zeroize();
        self.rounds.zeroize();
    }
}

impl ChaChaVR {
    fn do_rounds(state: &mut [u32; 16], rounds: u32){
        for _ in 0..(rounds / 2) {
            unsafe {
                let ptr = state.as_mut_ptr();
                // Столбцы
                Self::quarter_round(&mut *ptr.add(0), &mut *ptr.add(4),  &mut *ptr.add(8),  &mut *ptr.add(12));
                Self::quarter_round(&mut *ptr.add(1), &mut *ptr.add(5),  &mut *ptr.add(9),  &mut *ptr.add(13));
                Self::quarter_round(&mut *ptr.add(2), &mut *ptr.add(6),  &mut *ptr.add(10), &mut *ptr.add(14));
                Self::quarter_round(&mut *ptr.add(3), &mut *ptr.add(7),  &mut *ptr.add(11), &mut *ptr.add(15));
                // Диагонали
                Self::quarter_round(&mut *ptr.add(0), &mut *ptr.add(5),  &mut *ptr.add(10), &mut *ptr.add(15));
                Self::quarter_round(&mut *ptr.add(1), &mut *ptr.add(6),  &mut *ptr.add(11), &mut *ptr.add(12));
                Self::quarter_round(&mut *ptr.add(2), &mut *ptr.add(7),  &mut *ptr.add(8),  &mut *ptr.add(13));
                Self::quarter_round(&mut *ptr.add(3), &mut *ptr.add(4),  &mut *ptr.add(9),  &mut *ptr.add(14));
            }
        }
    }
    /// Дополнительное смешивание состояний (pre_mix_state)
    /// Выполняет дополнительные раунды для усиления эффекта лавинной реакции.
    fn pre_mix_state(state: &mut [u32; 16], mix_rounds: u32) {
        // mix_rounds должно быть четным. Каждая итерация выполняет раунды по столбцам и раунды по диагонали.
        Self::do_rounds(state,mix_rounds)
    }
    
    /// Создает новый экземпляр ChaChaVR.
    /// - 'key': 16 или 32 байта.
    /// - 'nonce': 8 или 12 байт.
    /// - 'rounds': любое четное число (>=2).
    pub fn new(key: &[u8], nonce: &[u8], rounds: u32) -> Result<Self, &'static str> {
        if rounds < 2 || rounds % 2 != 0 {
            return Err("Rounds must be an even number and >=2");
        }
        if key.len() != 16 && key.len() != 32 {
            return Err("Key length must be 16 or 32 bytes");
        }
        if nonce.len() != 8 && nonce.len() != 12 {
            return Err("Nonce length must be 8 or 12 bytes");
        }
        
        let mut state = [0u32; 16];
        if key.len() == 16 {
            // Используйте панель "expand 16-byte k"
            let pad = b"expand 16-byte k"; // Точно 16 байт
            state[0] = u32::from_le_bytes([pad[0], pad[1], pad[2], pad[3]]);
            state[1] = u32::from_le_bytes([pad[4], pad[5], pad[6], pad[7]]);
            state[2] = u32::from_le_bytes([pad[8], pad[9], pad[10], pad[11]]);
            state[3] = u32::from_le_bytes([pad[12], pad[13], pad[14], pad[15]]);
            // Ключ в состояние 0..7
            for i in 0..4 {
                state[4 + i] = u32::from_le_bytes(key[4 * i..4 * i + 4].try_into().unwrap());
            }
            // Дупликат из 8..11
            for i in 0..4 {
                state[8 + i] = state[4 + i];
            }
        } else {
            // Используйте панель "expand 32-byte k"
            let pad = b"expand 32-byte k"; // Точно 16 байт
            state[0] = u32::from_le_bytes([pad[0], pad[1], pad[2], pad[3]]);
            state[1] = u32::from_le_bytes([pad[4], pad[5], pad[6], pad[7]]);
            state[2] = u32::from_le_bytes([pad[8], pad[9], pad[10], pad[11]]);
            state[3] = u32::from_le_bytes([pad[12], pad[13], pad[14], pad[15]]);
            for i in 0..8 {
                state[4 + i] = u32::from_le_bytes(key[4 * i..4 * i + 4].try_into().unwrap());
            }
        }
        
        // Инициализировать одноразовый номер и счетчик.
        if nonce.len() == 8 {
            state[12] = 0;
            state[13] = 0;
            state[14] = u32::from_le_bytes(nonce[0..4].try_into().unwrap());
            state[15] = u32::from_le_bytes(nonce[4..8].try_into().unwrap());
        } else {
            //Для 96-битного nonce счетчик занимает состояние [12], а nonce заполняет состояние [13..15].
            state[12] = 0;
            state[13] = u32::from_le_bytes(nonce[0..4].try_into().unwrap());
            state[14] = u32::from_le_bytes(nonce[4..8].try_into().unwrap());
            state[15] = u32::from_le_bytes(nonce[8..12].try_into().unwrap());
        }
        
        // Дополнительно перемешивают смесь для усиления диффузии.
        Self::pre_mix_state(&mut state, 4);
        
        Ok(Self {
            rounds,
            state,
            keystream: [0u8; 64],
            pos: 64, // запускать генерацию блока потока ключей при первом использовании
        })
    }
    
    #[inline(always)]
    fn quarter_round(a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32) {
        *a = a.wrapping_add(*b);
        *d ^= *a;
        *d = d.rotate_left(16);
        
        *c = c.wrapping_add(*d);
        *b ^= *c;
        *b = b.rotate_left(12);
        
        *a = a.wrapping_add(*b);
        *d ^= *a;
        *d = d.rotate_left(8);
        
        *c = c.wrapping_add(*d);
        *b ^= *c;
        *b = b.rotate_left(7);
    }
    
    /// Генерирует новый 64-байтовый блок ключевого потока.
    fn process_block(&mut self) {
        let mut working_state = self.state;
        Self::do_rounds(&mut working_state, self.rounds);
        for i in 0..16 {
            working_state[i] = working_state[i].wrapping_add(self.state[i]);
        }
        for (i, word) in working_state.iter().enumerate() {
            self.keystream[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
        }
    }
    
    /// Зашифровывает/расшифровывает входной буфер (XOR с потоком ключей).
    pub fn process(&mut self, input: &[u8]) -> Vec<u8> {
        let mut output = Vec::with_capacity(input.len());
        let mut remaining = input;
        while !remaining.is_empty() {
            if self.pos >= 64 {
                self.process_block();
                // Увеличить счетчик блоков в состоянии [12]; обработать переполнение в состоянии [13]
                self.state[12] = self.state[12].wrapping_add(1);
                if self.state[12] == 0 {
                    self.state[13] = self.state[13].wrapping_add(1);
                }
                self.pos = 0;
            }
            let chunk = remaining.len().min(64 - self.pos);
            let keystream_chunk = &self.keystream[self.pos..self.pos + chunk];
            for i in 0..chunk {
                output.push(remaining[i] ^ keystream_chunk[i]);
            }
            self.pos += chunk;
            remaining = &remaining[chunk..];
        }
        output
    }
    
    /// Простая обфускация путем сдвига байтов.
    pub fn byte_shift(data: &mut [u8], shift: u8) {
        for byte in data.iter_mut() {
            *byte = byte.wrapping_add(shift);
        }
    }
    
    /// Обфусцирует внутренний ключевой поток.
    pub fn obfuscate_keystream(&mut self, shift: u8) {
        Self::byte_shift(&mut self.keystream, shift);
    }
}

// ====================
// Реальные тесты с многопоточностью с использованием Rayon
// ====================

use std::sync::atomic::{AtomicUsize, Ordering};

/// Вычисляет расстояние Хэмминга между двумя байтовыми слайсами.
fn hamming_distance(a: &[u8], b: &[u8]) -> u32 {
    a.iter()
     .zip(b.iter())
     .map(|(x, y)| (x ^ y).count_ones())
     .sum()
}

/// Запускает тесты KAT, Avalanche и Speed для одного файла.
fn test_file(path: &Path, rounds: u32) {
    // Прочитайте весь файл (для очень больших файлов рассмотрите возможность потоковой передачи)
    let mut file = File::open(path).expect("Cannot open file");
    let mut data = Vec::new();
    file.read_to_end(&mut data).expect("Cannot read file");
    
    println!("File: {:?} ({} bytes)", path.file_name().unwrap(), data.len());
    
    // Сгенерируйте случайный ключ и одноразовый номер для теста этого файла.
    let mut rng = rand::rng();
    let mut key_bytes = [0u8; 32];
    rng.fill(&mut key_bytes);
    let key = SecretBox::new(Box::new(key_bytes));
    
    let mut nonce = [0u8; 12];
    rng.fill(&mut nonce);
    
    // --- KAT ---
    let mut cipher1 = ChaChaVR::new(key.expose_secret(), &nonce, rounds)
        .expect("Failed to init cipher");
    let ct1 = cipher1.process(&data);
    let mut cipher2 = ChaChaVR::new(key.expose_secret(), &nonce, rounds)
        .expect("Failed to init cipher");
    let ct2 = cipher2.process(&data);
    if ct1 == ct2 {
        println!("  KAT PASS");
    } else {
        println!("  KAT FAIL");
    }
    // Тест расшифровки
    let mut decipher = ChaChaVR::new(key.expose_secret(), &nonce, rounds)
        .expect("Failed to init cipher");
    let recovered = decipher.process(&ct1);
    if recovered == data {
        println!("  Decryption PASS");
    } else {
        println!("  Decryption FAIL");
    }
    
    // --- Тест Avalanche ---
    // Используйте первые 64 байта файла (или весь файл, если < 64 байта)
    let block = if data.len() >= 64 { &data[..64] } else { &data[..] };
    let mut cipher_orig = ChaChaVR::new(key.expose_secret(), &nonce, rounds)
        .expect("Failed to init cipher");
    let ct_orig = cipher_orig.process(block);
    
    let key_bits = key_bytes.len() * 8;
    let mut total_distance = 0u32;
    for bit in 0..key_bits {
        let mut modified_key = key_bytes.clone();
        let byte_pos = bit / 8;
        let bit_pos = bit % 8;
        modified_key[byte_pos] ^= 1 << bit_pos;
        let mut cipher_mod = ChaChaVR::new(&modified_key, &nonce, rounds)
            .expect("Failed to init cipher");
        let ct_mod = cipher_mod.process(block);
        total_distance += hamming_distance(&ct_orig, &ct_mod);
    }
    let avg_distance = total_distance as f64 / (key_bits as f64);
    println!("  Avalanche: {:.2} bits per key bit flip", avg_distance);
    
    // --- Тест скорости ---
    let start = Instant::now();
    let mut cipher_speed = ChaChaVR::new(key.expose_secret(), &nonce, rounds)
        .expect("Failed to init cipher");
    let _ = cipher_speed.process(&data);
    let elapsed = start.elapsed();
    let mb = data.len() as f64 / (1024.0 * 1024.0);
    let throughput = mb / elapsed.as_secs_f64();
    println!("  Speed: {:.3} MB/s (elapsed: {:.3} s)", throughput, elapsed.as_secs_f64());
    println!();
}

/// Запускает реальные тесты для всех файлов в заданном каталоге с использованием Rayon для параллельной обработки.
/// Каждый файл обрабатывается полностью в своем собственном потоке.
fn real_world_tests(dir_path: &str, rounds: u32) {
    let paths: Vec<_> = fs::read_dir(dir_path)
        .expect("Cannot read directory")
        .filter_map(|res| {
            res.ok().and_then(|entry| {
                let path = entry.path();
                if path.is_file() { Some(path) } else { None }
            })
        })
        .collect();
    
    if paths.is_empty() {
        println!("No files found in {}", dir_path);
        return;
    }
    
    println!("Found {} files in {}", paths.len(), dir_path);
    
    // Параллельная обработка файлов с помощью Rayon.
    paths.par_iter().for_each(|path| {
        test_file(path, rounds);
    });
}

fn main() {
    // Установите тестовый каталог и раунды здесь.
    let rounds: u8 = 2;
    let dir_path: &str = r"E:\test"; // измените на свой тестовый каталог
    
    println!("=== Real-World Tests ===");
    real_world_tests(dir_path, rounds.into());
}