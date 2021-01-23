use ope::OrderPreservingEncryption;
use rand_core::{OsRng, RngCore};
use std::collections::HashMap;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 3 {
        println!("The proper way to run this program is:\n  cargo run --release <NUM_INTS> <EXPANSION_FACTOR>.\n\nTry cargo run --release 100000 3");
        std::process::exit(0);
    }

    let num_ints: usize = args[1]
        .parse()
        .expect("Must enter a valid positive integer for number of integers to test");
    let expansion_factor: usize = args[2]
        .parse()
        .expect("Must enter a valid positive integer for the expansion factor");

    if expansion_factor < 1 {
        panic!("Expansion factor must be at least 1");
    }

    test_ordering(num_ints, 1, expansion_factor);
}

fn test_ordering(num_ints: usize, block_size: usize, expansion_factor: usize) {
    let mut rng = OsRng;

    let ope = OrderPreservingEncryption::new(block_size, expansion_factor);

    println!(
        "Order-preserving encryption on {} u64s with expansion factor = {}:",
        num_ints, expansion_factor
    );
    println!(
        "- Ciphertext length: {} bytes",
        ope.ciphertext_len_in_bytes()
    );
    println!(
        "- Upper bound on expected failure rate: 1 / 2^{}\n",
        ope.inverted_log_failure_rate()
    );

    let key = ope.keygen(&mut rng);

    // Pick random ints

    println!(
        "Randomly sampling {} 64-bit integers and sorting them...",
        num_ints
    );
    let mut plaintexts = vec![];
    for _ in 0..num_ints {
        plaintexts.push(rng.next_u64());
    }
    plaintexts.sort_unstable();
    plaintexts.dedup(); // Get rid of repeats

    let plaintext_strings: Vec<String> = plaintexts.iter().map(|x| x.to_string()).collect();
    print_vector_preview(&plaintext_strings);

    println!(
        "Encrypting using order-preserving encryption with expansion factor = {}...",
        expansion_factor
    );
    let mut ciphertexts = vec![];
    let mut plaintexts_to_ciphertexts = HashMap::new();
    for &plaintext in &plaintexts {
        let ciphertext = ope.encrypt(&key, plaintext);
        ciphertexts.push(ciphertext.clone());
        plaintexts_to_ciphertexts.insert(plaintext, ciphertext.clone());
    }
    ciphertexts.sort();

    print_vector_preview(&ciphertexts);

    let mut ciphertexts_map = HashMap::new();
    for (i, ciphertext) in ciphertexts.iter().enumerate() {
        ciphertexts_map.insert(ciphertext.clone(), i);
    }

    let mut ordering = vec![];
    for &plaintext in &plaintexts {
        let ciphertext = plaintexts_to_ciphertexts
            .get(&plaintext)
            .expect("Could not find corresponding ciphertext");
        let &value = ciphertexts_map
            .get(&ciphertext.clone())
            .expect("Could not find ordering for ciphertext");

        ordering.push(value);
    }

    println!(
        "Printing the ordering of these ciphertexts (relative to original plaintext ordering):"
    );
    println!("> [{}]", abbreviate(&ordering[..]));
}

fn print_vector_preview(arr: &[String]) {
    if arr.len() < 5 {
        println!("{:?}", arr);
        return;
    }

    println!(
        "> [{}, {}, and {} more...]\n",
        arr[0],
        arr[1],
        arr.len() - 2
    );
}

fn abbreviate(arr: &[usize]) -> String {
    let mut result = String::new();

    let n = arr.len();
    let mut i = 0;
    let mut j;
    while i < n {
        // start iteration from the
        // ith array element
        j = i;

        // loop until arr[i+1] == arr[i]
        // and increment j
        while (j + 1 < n) && (arr[j + 1] == arr[j] + 1) {
            j += 1;
        }

        // if the program do not enter into
        // the above while loop this means that
        // (i+1)th element is not consecutive
        // to i th element
        if i == j {
            result = [result, arr[i].to_string(), String::from(" ")].join("");

            // increment i for next iteration
            i += 1;
        } else {
            let comma = match j + 1 >= n {
                true => String::from(""),
                false => String::from(", "),
            };

            // print the consecutive range found
            result = [
                result,
                arr[i].to_string(),
                String::from(" -> "),
                arr[j].to_string(),
                comma,
            ]
            .join("");

            // move i jump directly to j+1
            i = j + 1;
        }
    }

    result
}
