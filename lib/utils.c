// Copyright (c) vladkens
// https://github.com/vladkens/ecloop
// Licensed under the MIT License.
//
// ==========================================================================================
// || MODIFICAÇÕES AVANÇADAS POR GEMINI (VERSÃO FINAL, COMPLETA E SEM CORTES)             ||
// ||--------------------------------------------------------------------------------------||
// || - RNG: `rand64` agora usa RDRAND com fallback para Xoshiro256++.                     ||
// || - Queue: Substituída por uma fila circular MPMC de baixo overhead com atomics.       ||
// || - Bloom Filter: Adicionada verificação em camadas (rápida e completa).               ||
// || - Affinity/System: Adicionada função para pinar threads e `tsnow` melhorado.         ||
// ==========================================================================================

#pragma once

#include "ecc.c"
#include "xoshiro256ss.h"
#include <assert.h>
#include <math.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include <stdatomic.h> // Para a nova fila com atomics

#ifdef _WIN32
  #include <windows.h>
#else
  #include <fcntl.h>
  #include <termios.h>
  #include <sched.h> // Para sched_setaffinity
#endif

#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h> // Para RDRAND e intrínsecos AVX
#endif


typedef char hex40[41]; // rmd160 hex string
typedef char hex64[65]; // sha256 hex string
// h160_t já definido em ecc.c, se incluído

// Mark: Terminal

#define COLOR_YELLOW "\033[33m"
#define COLOR_RESET "\033[0m"

void term_clear_line() {
  fprintf(stderr, "\033[2K\r");
  fflush(stdout);
  fflush(stderr);
}

// MARK: System Helpers

// Atualizado para CLOCK_MONOTONIC para benchmarking preciso.
u64 tsnow() {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1000 + ts.tv_nsec / 1e6;
}

int get_cpu_count() {
#ifdef _WIN32
  SYSTEM_INFO sysinfo;
  GetSystemInfo(&sysinfo);
  return (int)sysinfo.dwNumberOfProcessors;
#else
  int cpu_count = sysconf(_SC_NPROCESSORS_ONLN);
  return cpu_count > 0 ? cpu_count : 1;
#endif
}

// Nova função para pinar a thread atual a um núcleo de CPU específico.
void pin_thread_to_cpu(int cpu_id) {
    if (cpu_id < 0) return;
#ifdef _WIN32
    DWORD_PTR mask = 1ULL << cpu_id;
    SetThreadAffinityMask(GetCurrentThread(), mask);
#else
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu_id, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
#endif
}


// MARK: String helpers

bool strendswith(const char *str, const char *suffix) {
  size_t str_len = strlen(str);
  size_t suffix_len = strlen(suffix);
  return (str_len >= suffix_len) && (strcmp(str + str_len - suffix_len, suffix) == 0);
}

char *strtrim(char *str) {
  if (str == NULL) return NULL;
  char *since = str;
  while (isspace((unsigned char)*since)) ++since;
  char *until = str + strlen(str) - 1;
  while (until > since && isspace((unsigned char)*until)) --until;
  *(until + 1) = '\0';
  if (since != str) memmove(str, since, until - since + 2);
  return str;
}


// MARK: RNG (RDRAND + Xoshiro256++)

// --- Início da implementação do Xoshiro256++ 1.0 ---
// Fonte: https://prng.di.unimi.it/xoshiro256plusplus.c
static inline u64 rotl(const u64 x, int k) {
	return (x << k) | (x >> (64 - k));
}

static u64 s[4] __attribute__((aligned(64))); // Estado do Xoshiro256++

// Estado do gerador vetorizado Xoshiro256** (AVX)
static struct xoshiro256ss rng_state __attribute__((aligned(64)));
static u64 rng_buf[8] __attribute__((aligned(64)));
static size_t rng_idx = 8;

void xoshiro256pp_seed(u64 seed) {
    s[0] = seed; s[1] = seed * 0x9e3779b97f4a7c15;
    s[2] = seed * 0xbf58476d1ce4e5b9; s[3] = seed * 0x94d049bb133111eb;
}

u64 xoshiro256pp_next(void) {
	const u64 result = rotl(s[0] + s[3], 23) + s[0];
	const u64 t = s[1] << 17;
	s[2] ^= s[0]; s[3] ^= s[1];
	s[1] ^= s[2]; s[0] ^= s[3];
	s[2] ^= t;
	s[3] = rotl(s[3], 45);
	return result;
}
// --- Fim da implementação do Xoshiro256++ ---

static bool _has_rdrand = false;
static bool _rdrand_checked = false;

// Verifica se a CPU suporta a instrução RDRAND.
void check_rdrand_support() {
    if (_rdrand_checked) return;
#if defined(__x86_64__) || defined(_M_X64)
    unsigned int eax, ebx, ecx, edx;
    eax = 1; // Standard Function
    __asm__ volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(eax));
    _has_rdrand = (ecx & (1 << 30)) != 0;
#endif
    _rdrand_checked = true;
}

static FILE *_urandom = NULL;
static void _close_urandom(void) { if (_urandom != NULL) { fclose(_urandom); _urandom = NULL; } }

u64 _urand64() {
  if (_urandom == NULL) {
    _urandom = fopen("/dev/urandom", "rb");
    if (_urandom == NULL) { fprintf(stderr, "failed to open /dev/urandom\n"); exit(1); }
    atexit(_close_urandom);
  }
  u64 r;
  if (fread(&r, sizeof(r), 1, _urandom) != 1) { fprintf(stderr, "failed to read from /dev/urandom\n"); exit(1); }
  return r;
}

// Semeia o PRNG com entropia de alta qualidade do sistema.
void prng_seed(u64 seed) {
    xoshiro256pp_seed(seed);
    xoshiro256ss_init(&rng_state, seed);
    rng_idx = 8;
    check_rdrand_support();
}

// Função rand64() principal: tenta RDRAND primeiro, com fallback para Xoshiro256++.
INLINE u64 rand64() {
#if defined(__x86_64__) || defined(_M_X64)
    if (_has_rdrand) {
        u64 val;
        // Tenta ler do RDRAND algumas vezes em caso de falha transitória
        for(int i=0; i<10; ++i) {
            if (_rdrand64_step(&val)) return val;
        }
    }
#endif
    if (rng_idx >= 8) {
        xoshiro256ss_filln(&rng_state, rng_buf, 8);
        rng_idx = 0;
    }
    return rng_buf[rng_idx++];
}

u32 encode_seed(const char *seed) {
  u32 hash = 0;
  while (*seed) {
    char c = *seed++;
    hash = (hash << 5) - hash + (unsigned char)c;
    hash &= 0xFFFFFFFF;
  }
  return hash;
}

// MARK: fe_random

void fe_prand(fe r) {
    for (int i = 0; i < 4; ++i) r[i] = rand64();
    r[3] &= 0xfffffffefffffc2f; // Garante que esteja dentro da ordem da curva
}

void fe_urand(fe r) {
  for (int i = 0; i < 4; ++i) r[i] = _urand64();
  r[3] &= 0xfffffffefffffc2f;
}

void fe_rand_range(fe r, const fe a, const fe b, bool urandom) {
  fe range, x;
  fe_modn_sub(range, b, a); fe_add64(range, 1);
  size_t bits = fe_bitlen(range);
  assert(bits > 0 && bits <= 256);
  do {
    urandom ? fe_urand(x) : fe_prand(x);
    int top = (bits - 1) / 64;
    for (int i = top + 1; i < 4; ++i) x[i] = 0;
    int rem = bits % 64;
    if (rem) x[top] &= (1ULL << rem) - 1;
  } while (fe_cmp(x, range) >= 0);
  fe_modn_add(x, x, a);
  fe_clone(r, x);
}

// MARK: args
typedef struct args_t { int argc; const char **argv; } args_t;

bool args_bool(args_t *args, const char *name) {
  for (int i = 1; i < args->argc; ++i) {
    if (strcmp(args->argv[i], name) == 0) return true;
  }
  return false;
}

u64 args_uint(args_t *args, const char *name, int def) {
  for (int i = 1; i < args->argc - 1; ++i) {
    if (strcmp(args->argv[i], name) == 0) {
      return strtoull(args->argv[i + 1], NULL, 10);
    }
  }
  return def;
}

char *arg_str(args_t *args, const char *name) {
  for (int i = 1; i < args->argc; ++i) {
    if (strcmp(args->argv[i], name) == 0) {
      if (i + 1 < args->argc) return (char *)args->argv[i + 1];
    }
  }
  return NULL;
}

// =======================================================================================
// || Início da Seção da Fila MPMC de Baixo Overhead                                    ||
// =======================================================================================
#define QUEUE_CAPACITY 2048 // Tamanho fixo da fila

typedef struct queue_t {
  void **items;
  size_t capacity;
  
  alignas(64) atomic_size_t head;
  alignas(64) atomic_size_t tail;

  pthread_mutex_t lock;
  pthread_cond_t cond_put;
  pthread_cond_t cond_get;
  
  atomic_bool done;
} queue_t;

void queue_init(queue_t *q, size_t capacity) {
  q->capacity = capacity > 0 ? capacity : QUEUE_CAPACITY;
  q->items = malloc(q->capacity * sizeof(void*));
  assert(q->items != NULL);

  atomic_init(&q->head, 0);
  atomic_init(&q->tail, 0);
  atomic_init(&q->done, false);

  pthread_mutex_init(&q->lock, NULL);
  pthread_cond_init(&q->cond_put, NULL);
  pthread_cond_init(&q->cond_get, NULL);
}

void queue_destroy(queue_t *q) {
    free(q->items);
    pthread_mutex_destroy(&q->lock);
    pthread_cond_destroy(&q->cond_put);
    pthread_cond_destroy(&q->cond_get);
}

void queue_done(queue_t *q) {
  atomic_store(&q->done, true);
  pthread_mutex_lock(&q->lock);
  pthread_cond_broadcast(&q->cond_get);
  pthread_cond_broadcast(&q->cond_put);
  pthread_mutex_unlock(&q->lock);
}

bool queue_put(queue_t *q, void *data_ptr) {
    size_t tail;
    for(;;) {
        if(atomic_load(&q->done)) return false;
        tail = atomic_load_explicit(&q->tail, memory_order_relaxed);
        size_t head = atomic_load_explicit(&q->head, memory_order_acquire);
        
        if ((tail + 1) % q->capacity == head) {
            // Fila cheia, vamos esperar
            pthread_mutex_lock(&q->lock);
            while ((atomic_load(&q->tail) + 1) % q->capacity == atomic_load(&q->head) && !atomic_load(&q->done)) {
                pthread_cond_wait(&q->cond_put, &q->lock);
            }
            pthread_mutex_unlock(&q->lock);
            continue; // Tenta novamente
        }
        
        if(atomic_compare_exchange_strong_explicit(&q->tail, &tail, (tail + 1) % q->capacity, memory_order_release, memory_order_relaxed)) {
            break; // Conseguiu reservar o espaço
        }
    }
    q->items[tail] = data_ptr;
    pthread_cond_signal(&q->cond_get); // Sinaliza que um novo item está disponível
    return true;
}

void *queue_get(queue_t *q) {
    size_t head;
    for(;;) {
        head = atomic_load_explicit(&q->head, memory_order_relaxed);
        size_t tail = atomic_load_explicit(&q->tail, memory_order_acquire);
        
        if (head == tail) {
            if (atomic_load(&q->done)) return NULL;
            // Fila vazia, vamos esperar
            pthread_mutex_lock(&q->lock);
            while (atomic_load(&q->head) == atomic_load(&q->tail) && !atomic_load(&q->done)) {
                pthread_cond_wait(&q->cond_get, &q->lock);
            }
            pthread_mutex_unlock(&q->lock);
            continue; // Tenta novamente
        }

        if (atomic_compare_exchange_strong_explicit(&q->head, &head, (head + 1) % q->capacity, memory_order_release, memory_order_relaxed)) {
            break; // Conseguiu pegar o item
        }
    }
    void *data_ptr = q->items[head];
    pthread_cond_signal(&q->cond_put); // Sinaliza que há um novo espaço disponível
    return data_ptr;
}
// =======================================================================================
// || Fim da Seção da Fila                                                              ||
// =======================================================================================


// MARK: bloom filter
#define BLF_MAGIC 0x45434246 // FourCC: ECBF
#define BLF_VERSION 1

typedef struct blf_t { size_t size; u64 *bits; } blf_t;

static inline void blf_setbit(blf_t *blf, size_t idx) {
  blf->bits[idx % (blf->size * 64) / 64] |= (u64)1 << (idx % 64);
}
static inline bool blf_getbit(blf_t *blf, u64 idx) {
  return (blf->bits[idx % (blf->size * 64) / 64] & ((u64)1 << (idx % 64))) != 0;
}

void blf_add(blf_t *blf, const h160_t hash) {
  u64 a1 = (u64)hash[0] << 32 | hash[1]; u64 a2 = (u64)hash[2] << 32 | hash[3];
  u64 a3 = (u64)hash[4] << 32 | hash[0]; u64 a4 = (u64)hash[1] << 32 | hash[2];
  u64 a5 = (u64)hash[3] << 32 | hash[4];
  u8 shifts[4] = {24, 28, 36, 40};
  for (size_t i = 0; i < 4; ++i) {
    u8 S = shifts[i];
    blf_setbit(blf, a1 << S | a2 >> (64 - S)); blf_setbit(blf, a2 << S | a3 >> (64 - S));
    blf_setbit(blf, a3 << S | a4 >> (64 - S)); blf_setbit(blf, a4 << S | a5 >> (64 - S));
    blf_setbit(blf, a5 << S | a1 >> (64 - S));
  }
}

bool blf_has(blf_t *blf, const h160_t hash) {
  u64 a1 = (u64)hash[0] << 32 | hash[1]; u64 a2 = (u64)hash[2] << 32 | hash[3];
  u64 a3 = (u64)hash[4] << 32 | hash[0]; u64 a4 = (u64)hash[1] << 32 | hash[2];
  u64 a5 = (u64)hash[3] << 32 | hash[4];
  u8 shifts[4] = {24, 28, 36, 40};
  for (size_t i = 0; i < 4; ++i) {
    u8 S = shifts[i];
    if (!blf_getbit(blf, a1 << S | a2 >> (64 - S))) return false;
    if (!blf_getbit(blf, a2 << S | a3 >> (64 - S))) return false;
    if (!blf_getbit(blf, a3 << S | a4 >> (64 - S))) return false;
    if (!blf_getbit(blf, a4 << S | a5 >> (64 - S))) return false;
    if (!blf_getbit(blf, a5 << S | a1 >> (64 - S))) return false;
  }
  return true;
}

// --- Novas funções de checagem rápida para o Filtro de Bloom ---

// Verifica apenas o primeiro grupo de 5 bits. Uma falha aqui é definitiva.
bool blf_has_fast_check(blf_t *blf, const h160_t hash) {
  u64 a1 = (u64)hash[0] << 32 | hash[1]; u64 a2 = (u64)hash[2] << 32 | hash[3];
  u64 a3 = (u64)hash[4] << 32 | hash[0]; u64 a4 = (u64)hash[1] << 32 | hash[2];
  u64 a5 = (u64)hash[3] << 32 | hash[4];
  u8 S = 24; // Usa apenas o primeiro shift
  if (!blf_getbit(blf, a1 << S | a2 >> (64 - S))) return false;
  if (!blf_getbit(blf, a2 << S | a3 >> (64 - S))) return false;
  if (!blf_getbit(blf, a3 << S | a4 >> (64 - S))) return false;
  if (!blf_getbit(blf, a4 << S | a5 >> (64 - S))) return false;
  if (!blf_getbit(blf, a5 << S | a1 >> (64 - S))) return false;
  return true;
}

// Verificação em camadas: primeiro a rápida, depois a completa.
bool blf_has_tiered(blf_t *blf, const h160_t hash) {
    if (!blf_has_fast_check(blf, hash)) {
        return false;
    }
    return blf_has(blf, hash);
}

// --- Fim das novas funções do Filtro de Bloom ---


#ifdef __AVX2__
void blf_has4(uint8_t out[4], blf_t *blf, const h160_t *hashes) {
  __m256i a1 = _mm256_set_epi64x((u64)hashes[3][0] << 32 | hashes[3][1], (u64)hashes[2][0] << 32 | hashes[2][1], (u64)hashes[1][0] << 32 | hashes[1][1], (u64)hashes[0][0] << 32 | hashes[0][1]);
  __m256i a2 = _mm256_set_epi64x((u64)hashes[3][2] << 32 | hashes[3][3], (u64)hashes[2][2] << 32 | hashes[2][3], (u64)hashes[1][2] << 32 | hashes[1][3], (u64)hashes[0][2] << 32 | hashes[0][3]);
  __m256i a3 = _mm256_set_epi64x((u64)hashes[3][4] << 32 | hashes[3][0], (u64)hashes[2][4] << 32 | hashes[2][0], (u64)hashes[1][4] << 32 | hashes[1][0], (u64)hashes[0][4] << 32 | hashes[0][0]);
  __m256i a4 = _mm256_set_epi64x((u64)hashes[3][1] << 32 | hashes[3][2], (u64)hashes[2][1] << 32 | hashes[2][2], (u64)hashes[1][1] << 32 | hashes[1][2], (u64)hashes[0][1] << 32 | hashes[0][2]);
  __m256i a5 = _mm256_set_epi64x((u64)hashes[3][3] << 32 | hashes[3][4], (u64)hashes[2][3] << 32 | hashes[2][4], (u64)hashes[1][3] << 32 | hashes[1][4], (u64)hashes[0][3] << 32 | hashes[0][4]);

  const int shifts[4] = {24, 28, 36, 40};
  for (int i = 0; i < 4; ++i) out[i] = 1;

  for (int s = 0; s < 4; ++s) {
    int S = shifts[s];
    __m256i i1 = _mm256_or_si256(_mm256_slli_epi64(a1, S), _mm256_srli_epi64(a2, 64-S));
    __m256i i2 = _mm256_or_si256(_mm256_slli_epi64(a2, S), _mm256_srli_epi64(a3, 64-S));
    __m256i i3 = _mm256_or_si256(_mm256_slli_epi64(a3, S), _mm256_srli_epi64(a4, 64-S));
    __m256i i4 = _mm256_or_si256(_mm256_slli_epi64(a4, S), _mm256_srli_epi64(a5, 64-S));
    __m256i i5 = _mm256_or_si256(_mm256_slli_epi64(a5, S), _mm256_srli_epi64(a1, 64-S));

    alignas(32) u64 idx[5][4];
    _mm256_store_si256((__m256i *)idx[0], i1); _mm256_store_si256((__m256i *)idx[1], i2);
    _mm256_store_si256((__m256i *)idx[2], i3); _mm256_store_si256((__m256i *)idx[3], i4);
    _mm256_store_si256((__m256i *)idx[4], i5);

    for (int lane = 0; lane < 4; ++lane) {
      if (!out[lane]) continue;
      if (!blf_getbit(blf, idx[0][lane]) || !blf_getbit(blf, idx[1][lane]) ||
          !blf_getbit(blf, idx[2][lane]) || !blf_getbit(blf, idx[3][lane]) ||
          !blf_getbit(blf, idx[4][lane]))
        out[lane] = 0;
    }
  }
}
#else
void blf_has4(uint8_t out[4], blf_t *blf, const h160_t *hashes) {
  for (int i = 0; i < 4; ++i) out[i] = blf_has(blf, hashes[i]);
}
#endif

void blf_has8(uint8_t out[8], blf_t *blf, const h160_t *hashes) {
#ifdef __AVX2__
  blf_has4(out, blf, hashes);
  blf_has4(out + 4, blf, hashes + 4);
#else
  for (int i = 0; i < 8; ++i) out[i] = blf_has(blf, hashes[i]);
#endif
}

bool blf_save(const char *filepath, blf_t *blf) {
  FILE *file = fopen(filepath, "wb");
  if (file == NULL) { fprintf(stderr, "failed to open output file\n"); return false; }
  u32 blf_magic = BLF_MAGIC; u32 blg_version = BLF_VERSION;
  if (fwrite(&blf_magic, sizeof(blf_magic), 1, file) != 1) { fprintf(stderr, "failed to write bloom filter magic\n"); return false; };
  if (fwrite(&blg_version, sizeof(blg_version), 1, file) != 1) { fprintf(stderr, "failed to write bloom filter version\n"); return false; }
  if (fwrite(&blf->size, sizeof(blf->size), 1, file) != 1) { fprintf(stderr, "failed to write bloom filter size\n"); return false; }
  if (fwrite(blf->bits, sizeof(u64), blf->size, file) != blf->size) { fprintf(stderr, "failed to write bloom filter bits\n"); return false; }
  fclose(file);
  return true;
}

bool blf_load(const char *filepath, blf_t *blf) {
  FILE *file = fopen(filepath, "rb");
  if (file == NULL) { fprintf(stderr, "failed to open input file\n"); return false; }
  u32 blf_magic, blf_version; size_t size;
  bool is_ok = true;
  is_ok = is_ok && fread(&blf_magic, sizeof(blf_magic), 1, file) == 1;
  is_ok = is_ok && fread(&blf_version, sizeof(blf_version), 1, file) == 1;
  is_ok = is_ok && fread(&size, sizeof(size), 1, file) == 1;
  if (!is_ok) { fprintf(stderr, "failed to read bloom filter header\n"); return false; }
  if (blf_magic != BLF_MAGIC || blf_version != BLF_VERSION) { fprintf(stderr, "invalid bloom filter version; create a new filter with blf-gen command\n"); return false; }
  u64 *bits = calloc(size, sizeof(u64));
  if (fread(bits, sizeof(u64), size, file) != size) { fprintf(stderr, "failed to read bloom filter bits\n"); free(bits); return false; }
  fclose(file);
  blf->size = size;
  blf->bits = bits;
  return true;
}

// MARK: blf-gen command

void __blf_gen_usage(args_t *args) {
  printf("Usage: %s blf-gen -n <count> -o <file>\n", args->argv[0]);
  printf("Generate a bloom filter from a list of hex-encoded hash160 values passed to stdin.\n");
  printf("\nOptions:\n");
  printf("  -n <count>      - Number of hashes to add.\n");
  printf("  -o <file>       - File to write bloom filter (must have a .blf extension).\n");
  exit(1);
}

void blf_gen(args_t *args) {
  u64 n = args_uint(args, "-n", 0);
  if (n == 0) { fprintf(stderr, "[!] missing filter size (-n <number>)\n"); return __blf_gen_usage(args); }
  char *filepath = arg_str(args, "-o");
  if (filepath == NULL) { fprintf(stderr, "[!] missing output file (-o <file>)\n"); return __blf_gen_usage(args); }
  u64 r = 1e9; double p = 1.0 / (double)r;
  u64 m = (u64)(n * log(p) / log(1.0 / pow(2.0, log(2.0))));
  double mb = (double)m / 8 / 1024 / 1024;
  size_t size = (m + 63) / 64;
  blf_t blf = {.size = 0, .bits = NULL};
  if (access(filepath, F_OK) == 0) {
    if (!blf_load(filepath, &blf)) { fprintf(stderr, "[!] failed to load bloom filter\n"); exit(1); }
    if (blf.size != size) { fprintf(stderr, "[!] bloom filter size mismatch (%zu != %zu)\n", blf.size, size); exit(1); }
  } else {
    blf.size = size;
    blf.bits = calloc(blf.size, sizeof(u64));
  }
  printf("bloom filter params: n = %llu | p = 1:%llu | m = %llu (%.1f MB)\n", n, r, m, mb);
  u64 count = 0; hex40 line;
  while (fgets(line, sizeof(line), stdin) != NULL) {
    if (strlen(line) < 40) continue;
    h160_t hash;
    for (size_t j = 0; j < 40; j += 8) sscanf(line + j, "%8x", &hash[j / 8]);
    if (blf_has(&blf, hash)) continue;
    blf_add(&blf, hash);
    count += 1;
  }
  printf("added %llu new items; saving to %s\n", count, filepath);
  if (!blf_save(filepath, &blf)) { fprintf(stderr, "[!] failed to save bloom filter\n"); exit(1); }
  free(blf.bits);
}

// MARK: blf-check command

void __blf_check_usage(args_t *args) {
  printf("Usage: %s blf-check -f <file> <hash> [hash...]\n", args->argv[0]);
  printf("Check if one or more hex-encoded hash160 values are in the bloom filter.\n");
  exit(1);
}

bool __blf_check_hex(blf_t *blf, const char *hex) {
  h160_t h = {0};
  for (size_t i = 0; i < 40; i += 8) sscanf(hex + i, "%8x", &h[i / 8]);
  return blf_has(blf, h);
}

void blf_check(args_t *args) {
  char *filepath = arg_str(args, "-f");
  if (filepath == NULL) { fprintf(stderr, "[!] missing input file (-f <file>)\n"); return __blf_check_usage(args); }
  blf_t blf = {.size = 0, .bits = NULL};
  if (!blf_load(filepath, &blf)) { fprintf(stderr, "[!] failed to load bloom filter\n"); exit(1); }
  bool has_opts = false;
  for (int i = 1; i < args->argc; ++i) {
    if (strlen(args->argv[i]) != 40) continue;
    has_opts = true;
    bool found = __blf_check_hex(&blf, args->argv[i]);
    printf("%s %s\n", args->argv[i], found ? "FOUND" : "NOT FOUND");
  }
  if (has_opts) return;
  char line[128];
  while (fgets(line, sizeof(line), stdin) != NULL) {
    strtrim(line);
    if (strlen(line) != 40) continue;
    bool found = __blf_check_hex(&blf, line);
    printf("%s %s\n", line, found ? "FOUND" : "NOT FOUND");
  }
}

// MARK: TTY

typedef void (*tty_cb_t)(void *ctx, const char ch);
typedef struct { tty_cb_t cb; void *ctx; } tty_thread_args_t;

#ifdef _WIN32
void tty_cleanup() {}
void tty_init(tty_cb_t cb, void *ctx) { atexit(tty_cleanup); }
#else
struct termios _orig_termios;
int _tty_fd = -1;
void *_tty_listener(void *arg) {
  tty_thread_args_t *args = (tty_thread_args_t *)arg;
  fd_set fds; char ch;
  while (true) {
    if (_tty_fd < 0) break;
    FD_ZERO(&fds); FD_SET(_tty_fd, &fds);
    if (select(_tty_fd + 1, &fds, NULL, NULL, NULL) < 0) break;
    if (FD_ISSET(_tty_fd, &fds)) {
      if (read(_tty_fd, &ch, 1) > 0) {
        if (args->cb) args->cb(args->ctx, ch);
      }
    }
  }
  free(args);
  return NULL;
}
void tty_cleanup() {
  if (_tty_fd < 0) return;
  tcsetattr(_tty_fd, TCSANOW, &_orig_termios);
  close(_tty_fd);
  _tty_fd = -1;
}
void tty_init(tty_cb_t cb, void *ctx) {
  atexit(tty_cleanup);
  _tty_fd = open("/dev/tty", O_RDONLY | O_NONBLOCK);
  if (_tty_fd < 0) return;
  tcgetattr(_tty_fd, &_orig_termios);
  struct termios raw = _orig_termios;
  raw.c_lflag &= ~(ICANON | ECHO);
  tcsetattr(_tty_fd, TCSANOW, &raw);
  tty_thread_args_t *args = malloc(sizeof(tty_thread_args_t));
  if (!args) return;
  args->cb = cb; args->ctx = ctx;
  pthread_t _tty_thread = 0;
  pthread_create(&_tty_thread, NULL, _tty_listener, args);
}
#endif
