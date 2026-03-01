from tokenizers import Tokenizer, models, trainers, pre_tokenizers, decoders
import os

TRAIN_FILE = "../dataset/splits/train_payloads.txt"
SAVE_DIR = "tokenizer"
VOCAB_SIZE = 8000

os.makedirs(SAVE_DIR, exist_ok=True)

# BPE tokenizer trained on XSS payloads
tokenizer = Tokenizer(models.BPE(unk_token="[UNK]"))
tokenizer.pre_tokenizer = pre_tokenizers.ByteLevel(add_prefix_space=False)
tokenizer.decoder = decoders.ByteLevel()

trainer = trainers.BpeTrainer(
    vocab_size=VOCAB_SIZE,
    min_frequency=2,
    special_tokens=["[PAD]", "[UNK]", "[CLS]", "[SEP]", "[MASK]"],
    show_progress=True
)

tokenizer.train([TRAIN_FILE], trainer)
tokenizer.save(os.path.join(SAVE_DIR, "tokenizer.json"))

# Test it
test_payloads = [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(document.cookie)>',
    'javascript:void(alert("XSS"))',
    '" onfocus=confirm(1) autofocus="',
]

print(f"\n[+] Vocab size: {tokenizer.get_vocab_size()}")
print(f"\n=== TOKENIZER TEST ===")
for p in test_payloads:
    encoded = tokenizer.encode(p)
    print(f"\nPayload: {p}")
    print(f"Tokens:  {encoded.tokens}")
    print(f"IDs:     {encoded.ids}")

print(f"\n[DONE] Tokenizer saved to {SAVE_DIR}/tokenizer.json")
