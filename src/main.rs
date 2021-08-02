use ckb_vm_pprof::quick_start;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let flag_parser = clap::App::new("ckb-vm-pprof")
        .version("0.1")
        .about("A pprof tool for CKB VM")
        .arg(
            clap::Arg::with_name("bin")
                .long("bin")
                .value_name("filename")
                .help("Specify the name of the executable")
                .required(true),
        )
        .arg(
            clap::Arg::with_name("arg")
                .long("arg")
                .value_name("arguments")
                .help("Pass arguments to binary")
                .multiple(true),
        )
        .get_matches();
    let fl_bin = flag_parser.value_of("bin").unwrap();
    let fl_arg: Vec<_> = flag_parser.values_of("arg").unwrap_or_default().collect();

    quick_start(fl_bin, fl_arg)?;

    Ok(())
}
