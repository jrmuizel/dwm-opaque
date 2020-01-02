use std::ptr::NonNull;

#[derive(Debug, Clone)]
#[repr(C)]
struct Rect {
	z: i32,
	left: f32,
	top: f32,
	right: f32,
	bottom: f32
}

extern "C" {
	fn wmain(cb: extern fn(NonNull<c_void>, NonNull<Rect>, usize), d: std::ptr::NonNull<c_void>);
}

use std::ffi::c_void;
use std::thread;
use std::sync::mpsc::channel;

extern "C" fn callback(d: std::ptr::NonNull<c_void>, rect: NonNull<Rect>, count: usize) {
	let mut d = d.cast::<Box<dyn FnMut(&[Rect])>>();
	let x: &mut Box<dyn FnMut(&[Rect])> = unsafe { d.as_mut() };
	x(unsafe { std::slice::from_raw_parts(rect.as_ptr(), count)} );
}

fn main() {
    let (tx, rx) = channel();
    let x = move |rects: &[Rect]| { tx.send(rects.to_vec()); };

    let child = thread::spawn(move || {

			      let mut x: Box<Box<dyn FnMut(&[Rect])>> = Box::new(Box::new(x));
			      let r: &mut Box<dyn FnMut(&[Rect])> = &mut x;
			      let r = r as *mut Box<dyn FnMut(&[Rect])>;

			      unsafe { wmain(callback, NonNull::new_unchecked(r).cast::<c_void>() ); }
    });
    loop {
    	let r = rx.recv().unwrap();
	println!("{:?}", r);
    }
}
