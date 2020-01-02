extern crate cc;

fn main() {
	cc::Build::new()
		.cpp(true)
		.define("UNICODE", None)
		.define("_UNICODE", None)
		.file("src/DWMLog.cpp")
		.compile("DWMLog");
}
