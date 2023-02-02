extern crate proc_macro;
use proc_macro::TokenStream;

#[proc_macro_attribute]
pub fn sysv64(args: TokenStream, input: TokenStream) -> TokenStream {
    sysv64_str(input).parse().unwrap()
}

#[proc_macro]
pub fn sysv64_type(input: TokenStream) -> TokenStream {
    sysv64_str(input).parse().unwrap()
}

fn sysv64_str(input: TokenStream) -> String {
    let mut output = String::new();
    let mut input = input.to_string();

    let input_splitted: Vec<&str> = input.split("fn").collect();

    output.push_str(&input_splitted[0]);
    #[cfg(target_arch = "x86_64")]
    output.push_str("extern \"sysv64\" fn");
    #[cfg(not(target_arch = "x86_64"))]
    output.push_str("extern \"C\" fn");
    output.push_str(&input_splitted[1]);

    output
}
