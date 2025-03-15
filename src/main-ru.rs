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
    rounds: u32,         // Число раундов (чётное, >=2)
    state: [u32; 16],    // Внутреннее состояние (16 слов по 32 бита)
    keystream: [u8; 64], // 64-байтовый блок keystream
    pos: usize,          // Текущая позиция в keystream (0..63)
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
    /// Дополнительное перемешивание состояния (pre_mix_state).
    /// Выполняет extra раунды для усиления лавинного эффекта.
    fn pre_mix_state(state: &mut [u32; 16], mix_rounds: u32) {
        // mix_rounds должно быть чётным; каждая итерация включает столбцовые и диагональные раунды.
        for _ in 0..(mix_rounds / 2) {
            unsafe {
                let ptr = state.as_mut_ptr();
                // Столбцовые раунды
                Self::quarter_round(&mut *ptr.add(0), &mut *ptr.add(4),  &mut *ptr.add(8),  &mut *ptr.add(12));
                Self::quarter_round(&mut *ptr.add(1), &mut *ptr.add(5),  &mut *ptr.add(9),  &mut *ptr.add(13));
                Self::quarter_round(&mut *ptr.add(2), &mut *ptr.add(6),  &mut *ptr.add(10), &mut *ptr.add(14));
                Self::quarter_round(&mut *ptr.add(3), &mut *ptr.add(7),  &mut *ptr.add(11), &mut *ptr.add(15));
                // Диагональные раунды
                Self::quarter_round(&mut *ptr.add(0), &mut *ptr.add(5),  &mut *ptr.add(10), &mut *ptr.add(15));
                Self::quarter_round(&mut *ptr.add(1), &mut *ptr.add(6),  &mut *ptr.add(11), &mut *ptr.add(12));
                Self::quarter_round(&mut *ptr.add(2), &mut *ptr.add(7),  &mut *ptr.add(8),  &mut *ptr.add(13));
                Self::quarter_round(&mut *ptr.add(3), &mut *ptr.add(4),  &mut *ptr.add(9),  &mut *ptr.add(14));
            }
        }
    }
    
    /// Создание нового экземпляра ChaChaVR.
    /// - `key`: 16 или 32 байта.
    /// - `nonce`: 8 или 12 байт.
    /// - `rounds`: любое чётное число (>=2).
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
            // Используем pad "expand 16-byte k"
            let pad = b"expand 16-byte k"; // ровно 16 байт
            state[0] = u32::from_le_bytes([pad[0], pad[1], pad[2], pad[3]]);
            state[1] = u32::from_le_bytes([pad[4], pad[5], pad[6], pad[7]]);
            state[2] = u32::from_le_bytes([pad[8], pad[9], pad[10], pad[11]]);
            state[3] = u32::from_le_bytes([pad[12], pad[13], pad[14], pad[15]]);
            // Загружаем ключ в state[4..7]
            for i in 0..4 {
                state[4 + i] = u32::from_le_bytes(key[4 * i..4 * i + 4].try_into().unwrap());
            }
            // Дублируем ключ для state[8..11]
            for i in 0..4 {
                state[8 + i] = state[4 + i];
            }
        } else {
            // Используем pad "expand 32-byte k"
            let pad = b"expand 32-byte k"; // ровно 16 байт
            state[0] = u32::from_le_bytes([pad[0], pad[1], pad[2], pad[3]]);
            state[1] = u32::from_le_bytes([pad[4], pad[5], pad[6], pad[7]]);
            state[2] = u32::from_le_bytes([pad[8], pad[9], pad[10], pad[11]]);
            state[3] = u32::from_le_bytes([pad[12], pad[13], pad[14], pad[15]]);
            for i in 0..8 {
                state[4 + i] = u32::from_le_bytes(key[4 * i..4 * i + 4].try_into().unwrap());
            }
        }
        
        // Инициализация nonce и счётчика
        if nonce.len() == 8 {
            state[12] = 0;
            state[13] = 0;
            state[14] = u32::from_le_bytes(nonce[0..4].try_into().unwrap());
            state[15] = u32::from_le_bytes(nonce[4..8].try_into().unwrap());
        } else {
            // Для 96-битного nonce счётчик занимает state[12], а nonce – state[13..15]
            state[12] = 0;
            state[13] = u32::from_le_bytes(nonce[0..4].try_into().unwrap());
            state[14] = u32::from_le_bytes(nonce[4..8].try_into().unwrap());
            state[15] = u32::from_le_bytes(nonce[8..12].try_into().unwrap());
        }
        
        // Применяем дополнительное перемешивание состояния (pre_mix_state) для усиления лавинного эффекта.
        Self::pre_mix_state(&mut state, 4);
        
        Ok(Self {
            rounds,
            state,
            keystream: [0u8; 64],
            pos: 64, // генерация нового блока происходит при первом вызове process()
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
    
    /// Генерация нового 64-байтового блока keystream.
    fn process_block(&mut self) {
        let mut working_state = self.state;
        for _ in 0..(self.rounds / 2) {
            unsafe {
                let ptr = working_state.as_mut_ptr();
                // Столбцовые раунды
                Self::quarter_round(&mut *ptr.add(0), &mut *ptr.add(4),  &mut *ptr.add(8),  &mut *ptr.add(12));
                Self::quarter_round(&mut *ptr.add(1), &mut *ptr.add(5),  &mut *ptr.add(9),  &mut *ptr.add(13));
                Self::quarter_round(&mut *ptr.add(2), &mut *ptr.add(6),  &mut *ptr.add(10), &mut *ptr.add(14));
                Self::quarter_round(&mut *ptr.add(3), &mut *ptr.add(7),  &mut *ptr.add(11), &mut *ptr.add(15));
                // Диагональные раунды
                Self::quarter_round(&mut *ptr.add(0), &mut *ptr.add(5),  &mut *ptr.add(10), &mut *ptr.add(15));
                Self::quarter_round(&mut *ptr.add(1), &mut *ptr.add(6),  &mut *ptr.add(11), &mut *ptr.add(12));
                Self::quarter_round(&mut *ptr.add(2), &mut *ptr.add(7),  &mut *ptr.add(8),  &mut *ptr.add(13));
                Self::quarter_round(&mut *ptr.add(3), &mut *ptr.add(4),  &mut *ptr.add(9),  &mut *ptr.add(14));
            }
        }
        for i in 0..16 {
            working_state[i] = working_state[i].wrapping_add(self.state[i]);
        }
        for (i, word) in working_state.iter().enumerate() {
            self.keystream[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
        }
    }
    
    /// Шифрование/расшифрование входного буфера (XOR с keystream).
    pub fn process(&mut self, input: &[u8]) -> Vec<u8> {
        let mut output = Vec::with_capacity(input.len());
        let mut remaining = input;
        while !remaining.is_empty() {
            if self.pos >= 64 {
                self.process_block();
                // Инкремент счетчика блока в state[12] (с переносом в state[13])
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
    
    /// Простая обфускация данных (байтовый сдвиг).
    pub fn byte_shift(data: &mut [u8], shift: u8) {
        for byte in data.iter_mut() {
            *byte = byte.wrapping_add(shift);
        }
    }
    
    /// Обфускация внутреннего keystream.
    pub fn obfuscate_keystream(&mut self, shift: u8) {
        Self::byte_shift(&mut self.keystream, shift);
    }
}

// ====================
// Реальные тесты (Real-World Tests) с использованием многопоточности через Rayon
// ====================

use std::sync::atomic::{AtomicUsize, Ordering};

/// Вычисляет расстояние Хэмминга между двумя срезами байтов.
fn hamming_distance(a: &[u8], b: &[u8]) -> u32 {
    a.iter()
     .zip(b.iter())
     .map(|(x, y)| (x ^ y).count_ones())
     .sum()
}

/// Тест для одного файла: выполняет KAT, Avalanche и Speed тесты.
fn test_file(path: &Path, rounds: u32) {
    // Считываем файл целиком (для очень больших файлов рекомендуется потоковое чтение)
    let mut file = File::open(path).expect("Не удалось открыть файл");
    let mut data = Vec::new();
    file.read_to_end(&mut data).expect("Не удалось прочитать файл");
    
    println!("Файл: {:?} ({} байт)", path.file_name().unwrap(), data.len());
    
    // Генерируем случайный ключ и nonce для данного файла
    let mut rng = rand::rng();
    let mut key_bytes = [0u8; 32];
    rng.fill(&mut key_bytes);
    let key = SecretBox::new(Box::new(key_bytes));
    
    let mut nonce = [0u8; 12];
    rng.fill(&mut nonce);
    
    // --- KAT тест ---
    let mut cipher1 = ChaChaVR::new(key.expose_secret(), &nonce, rounds)
        .expect("Ошибка инициализации шифра");
    let ct1 = cipher1.process(&data);
    let mut cipher2 = ChaChaVR::new(key.expose_secret(), &nonce, rounds)
        .expect("Ошибка инициализации шифра");
    let ct2 = cipher2.process(&data);
    if ct1 == ct2 {
        println!("  KAT PASS");
    } else {
        println!("  KAT FAIL");
    }
    // Тест расшифровки
    let mut decipher = ChaChaVR::new(key.expose_secret(), &nonce, rounds)
        .expect("Ошибка инициализации шифра");
    let recovered = decipher.process(&ct1);
    if recovered == data {
        println!("  Расшифровка PASS");
    } else {
        println!("  Расшифровка FAIL");
    }
    
    // --- Avalanche тест ---
    // Берем первые 64 байта файла (если файл меньше 64 байт, то используем весь)
    let block = if data.len() >= 64 { &data[..64] } else { &data[..] };
    let mut cipher_orig = ChaChaVR::new(key.expose_secret(), &nonce, rounds)
        .expect("Ошибка инициализации шифра");
    let ct_orig = cipher_orig.process(block);
    
    let key_bits = key_bytes.len() * 8;
    let mut total_distance = 0u32;
    for bit in 0..key_bits {
        let mut modified_key = key_bytes;
        let byte_pos = bit / 8;
        let bit_pos = bit % 8;
        modified_key[byte_pos] ^= 1 << bit_pos;
        let mut cipher_mod = ChaChaVR::new(&modified_key, &nonce, rounds)
            .expect("Ошибка инициализации шифра");
        let ct_mod = cipher_mod.process(block);
        total_distance += hamming_distance(&ct_orig, &ct_mod);
    }
    let avg_distance = total_distance as f64 / (key_bits as f64);
    println!("  Avalanche: {:.2} бит на флип бита ключа", avg_distance);
    
    // --- Speed тест ---
    let start = Instant::now();
    let mut cipher_speed = ChaChaVR::new(key.expose_secret(), &nonce, rounds)
        .expect("Ошибка инициализации шифра");
    let _ = cipher_speed.process(&data);
    let elapsed = start.elapsed();
    let mb = data.len() as f64 / (1024.0 * 1024.0);
    let throughput = mb / elapsed.as_secs_f64();
    println!("  Скорость: {:.3} MB/s (время: {:.3} с)", throughput, elapsed.as_secs_f64());
    println!();
}

/// Многопоточная обработка файлов из указанной директории с использованием Rayon.
/// Каждый файл обрабатывается независимо.
fn real_world_tests(dir_path: &str, rounds: u32) {
    let paths: Vec<_> = fs::read_dir(dir_path)
        .expect("Не удалось прочитать директорию")
        .filter_map(|res| {
            res.ok().and_then(|entry| {
                let path = entry.path();
                if path.is_file() { Some(path) } else { None }
            })
        })
        .collect();
    
    if paths.is_empty() {
        println!("В директории {} не найдено файлов", dir_path);
        return;
    }
    
    println!("Найдено {} файлов в {}", paths.len(), dir_path);
    
    // Обработка файлов параллельно с использованием Rayon.
    paths.par_iter().for_each(|path| {
        test_file(path, rounds);
    });
}

fn main() {
    // Запускаем тесты в области видимости, чтобы секретные данные быстро уничтожались.
    {
        // Задайте свою директорию с тестовыми файлами (например, "test_data")
        let rounds = 42;
        let dir_path = "test_data"; // измените на нужную директорию
        
        println!("=== Реальные тесты ===");
        real_world_tests(dir_path, rounds);
    }
}
