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

use minifb::{Window, WindowOptions, Scale};
use raqote::{DrawTarget, SolidSource, Source, DrawOptions, PathBuilder, Transform, StrokeStyle};
const WIDTH: usize = 400;
const HEIGHT: usize = 400;
fn main() {
    let (tx, rx) = channel();
    let x = move |rects: &[Rect]| { tx.send(rects.to_vec()); };

    let child = thread::spawn(move || {

			      let mut x: Box<Box<dyn FnMut(&[Rect])>> = Box::new(Box::new(x));
			      let r: &mut Box<dyn FnMut(&[Rect])> = &mut x;
			      let r = r as *mut Box<dyn FnMut(&[Rect])>;

			      unsafe { wmain(callback, NonNull::new_unchecked(r).cast::<c_void>() ); }
    });
    let mut dt = DrawTarget::new(WIDTH as i32, HEIGHT as i32);
    dt.set_transform(&Transform::create_scale(0.1, 0.1));
    let mut window = Window::new("Opaque", WIDTH, HEIGHT, WindowOptions::default()).unwrap();
    window.limit_update_rate(None);
    loop {
    	let mut rects = rx.recv().unwrap();
	dt.clear(SolidSource::from_unpremultiplied_argb(0xff, 0xff, 0xff, 0xff));
	//println!("{:#?}", rects);
	for r in rects {
		let mut pb = PathBuilder::new();
		pb.rect(r.left, r.top, r.right - r.left, r.bottom - r.top);
		let path = pb.finish();
		dt.fill(&path, &Source::Solid(SolidSource::from_unpremultiplied_argb(0x20, 0, 0xff, 0)),
			&DrawOptions::new());
		dt.stroke(&path, &Source::Solid(SolidSource::from_unpremultiplied_argb(0xff, 0, 0, 0)),
			&StrokeStyle{width: 5., ..Default::default()}, &DrawOptions::new());
	}
	window.update_with_buffer(dt.get_data(), WIDTH, HEIGHT).unwrap();
    }
}
