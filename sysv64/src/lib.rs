extern crate proc_macro;
use proc_macro::TokenStream;

#[proc_macro_attribute]
pub fn sysv64(_args: TokenStream, input: TokenStream) -> TokenStream {
    let mut output = String::new();
    let input = input.to_string();

    let input_splitted: Vec<&str> = input.split("fn").collect();

    output.push_str("#[cfg(target_arch = \"x86_64\")]\n");
    output.push_str(&input_splitted[0]);
    output.push_str("extern \"sysv64\" fn");
    output.push_str(&input_splitted[1]);
    output.push_str("#[cfg(not(target_arch = \"x86_64\"))]\n");
    output.push_str(&input_splitted[0]);
    output.push_str("extern \"C\" fn");
    output.push_str(&input_splitted[1]);

    output.parse().unwrap()
}

#[proc_macro]
pub fn sysved64_type(input: TokenStream) -> TokenStream {
    let mut output = String::new();
    let input = input.to_string();

    output.push_str("extern \"sysv64\" ");
    output.push_str(&input);

    output.parse().unwrap()
}

#[proc_macro]
pub fn sysvno64_type(input: TokenStream) -> TokenStream {
    let mut output = String::new();
    let input = input.to_string();

    output.push_str("extern \"C\" ");
    output.push_str(&input);

    output.parse().unwrap()
}
