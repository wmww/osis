//! Drawing into the view's surface: Vello over wgpu, as masonry_winit draws a desktop window.

use ndk::native_window::NativeWindow;
use osis_kit::masonry::peniko::Color;
use osis_kit::masonry::vello::kurbo::Affine;
use osis_kit::masonry::vello::util::{RenderContext, RenderSurface};
use osis_kit::masonry::vello::wgpu::rwh::{DisplayHandle, HandleError, HasDisplayHandle, HasWindowHandle, WindowHandle};
use osis_kit::masonry::vello::{AaConfig, AaSupport, RenderParams, Renderer, RendererOptions, Scene, wgpu};

/// The view's native window as a wgpu surface target.
struct Window(NativeWindow);

impl HasWindowHandle for Window {
    fn window_handle(&self) -> Result<WindowHandle<'_>, HandleError> {
        self.0.window_handle()
    }
}

impl HasDisplayHandle for Window {
    fn display_handle(&self) -> Result<DisplayHandle<'_>, HandleError> {
        Ok(DisplayHandle::android())
    }
}

pub struct Gpu {
    cx: RenderContext,
    surface: Option<RenderSurface<'static>>,
    renderer: Option<Renderer>,
}

impl Gpu {
    pub fn new() -> Gpu {
        Gpu { cx: RenderContext::new(), surface: None, renderer: None }
    }

    /// Draws into `window` from now on.
    pub fn attach(&mut self, window: NativeWindow, width: u32, height: u32) -> Result<(), String> {
        // the old surface holds the window: drop it first (ERROR_NATIVE_WINDOW_IN_USE_KHR)
        self.surface = None;
        if width == 0 || height == 0 {
            return Ok(());
        }
        let s = pollster::block_on(self.cx.create_surface(Window(window), width, height, wgpu::PresentMode::AutoVsync)).map_err(|e| e.to_string())?;
        self.surface = Some(s);
        Ok(())
    }

    /// The surface is gone (the app went to the background).
    pub fn detach(&mut self) {
        self.surface = None;
    }

    pub fn attached(&self) -> bool {
        self.surface.is_some()
    }

    /// Draws `scene` (in logical pixels) at `scale` over `base`.
    pub fn render(&mut self, scene: &Scene, scale: f64, base: Color) {
        let Some(surface) = &mut self.surface else { return };
        let scaled;
        let scene = if scale == 1.0 {
            scene
        } else {
            let mut s = Scene::new();
            s.append(scene, Some(Affine::scale(scale)));
            scaled = s;
            &scaled
        };
        let Some(dev) = self.cx.devices.get(surface.dev_id) else { return };
        let (device, queue) = (&dev.device, &dev.queue);
        let renderer = match &mut self.renderer {
            Some(r) => r,
            None => match Renderer::new(device, RendererOptions { antialiasing_support: AaSupport::area_only(), ..Default::default() }) {
                Ok(r) => self.renderer.insert(r),
                Err(e) => {
                    log::error!("renderer: {e}");
                    return;
                }
            },
        };
        let params = RenderParams { base_color: base, width: surface.config.width, height: surface.config.height, antialiasing_method: AaConfig::Area };
        if let Err(e) = renderer.render_to_texture(device, queue, scene, &surface.target_view, &params) {
            log::error!("render: {e}");
            return;
        }
        let texture = match surface.surface.get_current_texture() {
            Ok(t) => t,
            Err(e) => {
                log::error!("surface texture: {e}");
                return;
            }
        };
        let mut encoder = device.create_command_encoder(&wgpu::CommandEncoderDescriptor { label: Some("Surface Blit") });
        surface.blitter.copy(device, &mut encoder, &surface.target_view, &texture.texture.create_view(&wgpu::TextureViewDescriptor::default()));
        queue.submit([encoder.finish()]);
        texture.present();
        if let Err(e) = device.poll(wgpu::PollType::Wait) {
            log::error!("gpu poll: {e}");
        }
    }
}
