#!/usr/bin/env python3
"""Token-soup fuzzer for test_parser. Emits one line of random JS-ish tokens per iteration."""
import random, sys

TOKENS = [
    # literals
    "0","1","1e10","0x1F","0b101","0o17","1_000","1n",".5","5.",
    "'a'",'"b"',"`${x}`","`a${b}c`","/re/g","/[/]/","true","false","null",
    "undefined","NaN","Infinity","this","super","new.target","import.meta",
    # identifiers / keywords
    "a","b","c","x","y","z","_","$","foo","bar","async","await","yield",
    "let","const","var","function","class","return","if","else","for",
    "while","do","switch","case","default","break","continue","try",
    "catch","finally","throw","typeof","instanceof","in","of","delete",
    "void","new","extends","static","get","set",
    # punctuation
    "(",")","{","}","[","]","<",">","=","==","===","!=","!==","=>",
    "+","-","*","/","%","**","++","--","&&","||","??","?.","!","~",
    "&","|","^","<<",">>",">>>","+=","-=","*=","/=","%=","**=",
    "&=","|=","^=","<<=",">>=",">>>=","&&=","||=","??=",
    ",",";",":","?","...","@","#","`",
    # malformed / tricky
    "\\u0041","\\x41","\u2028","\u2029","\0","\t","  ","//c\n","/*c*/",
]

def gen_line(rng, max_len=40):
    n = rng.randint(1, max_len)
    return " ".join(rng.choice(TOKENS) for _ in range(n))

def main():
    seed = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 1000
    rng = random.Random(seed)
    for _ in range(count):
        # avoid raw newlines breaking the line protocol
        print(gen_line(rng).replace("\n", " ").replace("\r", " "))

if __name__ == "__main__":
    main()
