//! Chats in the window: home's join field, the open chat (its newest messages, live through the
//! chat's watch, and a composer). What is read and written goes through `crate::chat`.

use super::content::{Block, ChipM, Content};
use super::{Act, CHAT_LOG, CHAT_REPLY, Msg, Ui};
use crate::chat::{self, Line};
use osis::Tid;
use osis_chat::Id;
use osis_kit::icons::Icon;
use osis_kit::masonry::core::{NewWidget, Properties, Widget, WidgetId, WidgetTag};
use osis_kit::masonry::kurbo::Point;
use osis_kit::masonry::properties::Padding;
use osis_kit::masonry::properties::types::{CrossAxisAlignment, Length};
use osis_kit::masonry::widgets::{Flex, Portal, SizedBox, TextAction, TextArea};
use osis_kit::masonry_winit::app::DriverCtx;
use osis_kit::widgets::style::{self, Text};
use osis_kit::widgets::{IconButton, Panel, PanelKind};
use std::collections::HashMap;

/// Messages a chat shows: the newest this many (older ones are not reachable from the window
/// yet). 0 would show nothing; all of them would re-read the whole history at every change.
const SHOWN: usize = 200;

/// The open chat's scrolling timeline.
const CHAT_SCROLL: WidgetTag<Portal<Flex>> = WidgetTag::new("chat-scroll");

/// What the clipboard's text is for (Android, `Act::Paste`).
#[cfg(target_os = "android")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PasteTo {
    Host,
    Join,
    Name,
    Send(Tid),
}

/// A chat text input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Input {
    /// A link to join by (home).
    Join,
    /// The name to send under.
    Name,
    Subject,
    Text,
}

/// What the chat inputs hold (kept across screens: a draft survives looking elsewhere).
#[derive(Debug, Default)]
pub(super) struct Compose {
    /// The inputs of the screen built.
    pub ids: HashMap<WidgetId, Input>,
    pub join: String,
    /// The name being typed (`None`: untouched, show the saved one).
    pub name: Option<String>,
    pub subject: String,
    pub text: String,
    pub reply: Option<Id>,
    /// A join is under way.
    pub joining: bool,
}

impl Compose {
    fn id_of(&self, i: Input) -> Option<WidgetId> {
        self.ids.iter().find(|(_, x)| **x == i).map(|(id, _)| *id)
    }

    /// The message input of the screen built.
    pub fn text_id(&self) -> Option<WidgetId> {
        self.id_of(Input::Text)
    }
}

/// "Mon 3 Nov 14:05", local.
fn when(utc_ms: u64) -> String {
    use crate::time::DAY;
    let l = crate::time::local_of(i64::try_from(utc_ms).unwrap_or(i64::MAX));
    format!("{} {}", crate::data::fmt_day(l.div_euclid(DAY)), crate::data::fmt_time(l))
}

impl Ui {
    /// A chat input in a field panel (it reports losing focus: the name saves then).
    fn chat_input(&mut self, i: Input, text: &str, placeholder: &str) -> NewWidget<Panel> {
        let (input, id) = style::input(&self.look, text, placeholder, Text::Body, false);
        let panel = NewWidget::new(Panel::new(input, self.look.clone(), PanelKind::Field, (8.0, 12.0)).report_blur(true));
        self.compose.ids.insert(id, i);
        self.blur_panels.insert(panel.id(), id);
        panel
    }

    fn name_shown(&self) -> String {
        self.compose.name.clone().unwrap_or_else(|| chat::my_name(&self.data.db).ok().flatten().unwrap_or_default())
    }

    /// Home's chat section under the list: the name and a link to join by.
    pub(super) fn join_section(&mut self) -> NewWidget<dyn Widget> {
        let look = self.look.clone();
        let name = self.name_shown();
        let join = self.compose.join.clone();
        let col = Flex::column()
            .cross_axis_alignment(CrossAxisAlignment::Fill)
            .with_gap(Length::px(look.sp(6.0)))
            .with_child(style::label(&look, "Join a chat", Text::Section))
            .with_child(self.chat_input(Input::Join, &join, "Paste an osis:// chat link, Enter joins"))
            .with_child(style::label(&look, "Your name in chats", Text::Small))
            .with_child(self.chat_input(Input::Name, &name, "Your name, Enter saves"));
        #[cfg(target_os = "android")]
        let col = self.android_join(col);
        NewWidget::new(col).erased()
    }

    /// Android's additions to the join section. A phone has no Ctrl+V, and winit 0.30 has no
    /// soft keyboard text on Android (notes/android.md), so the clipboard stands in for typing:
    /// the host (the store starts without one), the link, the name.
    #[cfg(target_os = "android")]
    fn android_join(&mut self, col: Flex) -> Flex {
        let look = self.look.clone();
        let col = match self.data.db.hosts().first() {
            Some(h) => col.with_child(style::label(&look, &format!("Host: {h}"), Text::Small)),
            None => col.with_child(style::label(&look, "No host yet: copy its quic:// address first", Text::Small)).with_child(self.paste_chip("Paste host address", PasteTo::Host)),
        };
        let row = Flex::row().with_gap(Length::px(look.sp(8.0))).with_child(self.paste_chip("Paste link and join", PasteTo::Join)).with_child(self.paste_chip("Paste name", PasteTo::Name));
        col.with_child(NewWidget::new(row))
    }

    #[cfg(target_os = "android")]
    fn paste_chip(&mut self, label: &str, to: PasteTo) -> NewWidget<dyn Widget> {
        let chip = NewWidget::new(osis_kit::widgets::Chip::new(label, None, osis_kit::widgets::ChipMark::Icon(Icon::Plus), self.look.clone()));
        self.act(chip, Act::Paste(to))
    }

    /// Uses the clipboard's text as `to` says (Android).
    #[cfg(target_os = "android")]
    pub(super) fn paste(&mut self, ctx: &mut DriverCtx<'_, '_>, to: PasteTo) -> osis::Result<()> {
        let text = crate::platform::clipboard().unwrap_or_default().trim().to_string();
        if text.is_empty() {
            return Err(osis::Error::Invalid("the clipboard holds no text".into()));
        }
        match to {
            PasteTo::Host => {
                let h: osis::HostAddr = text.parse().map_err(|e| osis::Error::Invalid(format!("not a host address: {e}")))?;
                self.data.db.add_host(&h)?;
                self.status(ctx, format!("host {h} added"));
            }
            PasteTo::Join => {
                self.compose.join = text;
                self.start_join(ctx);
            }
            PasteTo::Name => {
                self.compose.name = Some(text);
                self.save_name()?;
            }
            PasteTo::Send(c) => {
                self.compose.text = text;
                self.send(ctx, c)?;
            }
        }
        Ok(())
    }

    /// An open chat: back, its name, the timeline, the composer.
    pub(super) fn chat_screen(&mut self, c: Tid) -> osis::Result<NewWidget<dyn Widget>> {
        let look = self.look.clone();
        let sp = |x: f64| look.sp(x);
        let back = NewWidget::new(IconButton::new(osis_kit::icons::Icon::Back, "Home", look.clone()));
        let bar = Flex::row()
            .with_gap(Length::px(sp(8.0)))
            .with_child(self.act(back, Act::Home))
            .with_child(style::label(&look, &chat::name(&self.data.db, c)?, Text::Title))
            .with_flex_spacer(1.0);
        let log = Flex::column().cross_axis_alignment(CrossAxisAlignment::Fill).with_child(self.slot_widget(CHAT_LOG));
        let log = NewWidget::new_with_props(log, Properties::new().with(Padding::all(sp(14.0))));
        let scroll = NewWidget::new_with_tag(Portal::new(log).constrain_horizontal(true).content_must_fill(true), CHAT_SCROLL);
        let log_panel = NewWidget::new(Panel::new(scroll, look.clone(), PanelKind::Panel, (0.0, 0.0)).fill_height(true));
        let (name, subject, text) = (self.name_shown(), self.compose.subject.clone(), self.compose.text.clone());
        let top = Flex::row()
            .with_gap(Length::px(sp(8.0)))
            .with_child(NewWidget::new(SizedBox::new(self.chat_input(Input::Name, &name, "Your name")).width(Length::px(200.0))))
            .with_flex_child(self.chat_input(Input::Subject, &subject, "Subject (optional)"), 1.0);
        let send = NewWidget::new(osis_kit::widgets::Chip::new("Send", None, osis_kit::widgets::ChipMark::Icon(Icon::Plus), look.clone()));
        let bottom = Flex::row()
            .with_gap(Length::px(sp(8.0)))
            .with_flex_child(self.chat_input(Input::Text, &text, "Message, Enter sends"), 1.0)
            .with_child(self.act(send, Act::Send(c)));
        #[cfg(target_os = "android")]
        let bottom = bottom.with_child(self.paste_chip("Paste and send", PasteTo::Send(c)));
        let composer = Flex::column()
            .cross_axis_alignment(CrossAxisAlignment::Fill)
            .with_gap(Length::px(sp(8.0)))
            .with_child(self.slot_widget(CHAT_REPLY))
            .with_child(NewWidget::new(top))
            .with_child(NewWidget::new(bottom));
        let composer = NewWidget::new(Panel::new(NewWidget::new(composer), look.clone(), PanelKind::Panel, (12.0, 14.0)));
        let col = Flex::column()
            .cross_axis_alignment(CrossAxisAlignment::Fill)
            .with_gap(Length::px(sp(10.0)))
            .with_child(NewWidget::new(bar))
            .with_flex_child(log_panel, 1.0)
            .with_child(composer)
            .with_child(self.status_widget());
        Ok(NewWidget::new_with_props(col, Properties::new().with(Padding::all(sp(16.0)))).erased())
    }

    /// The timeline's model.
    pub(super) fn chat_log_content(&self, c: Tid) -> osis::Result<Content> {
        let lines = chat::recent(&self.data.db, c, SHOWN)?;
        let mut blocks = Vec::new();
        if lines.is_empty() {
            blocks.push(Block::Line("No messages yet.".into()));
        } else if lines.len() == SHOWN {
            blocks.push(Block::Line(format!("The newest {SHOWN} messages.")));
        }
        blocks.push(Block::Messages(lines));
        Ok(Content { blocks })
    }

    /// Above the composer: who you post as, and the message being answered.
    pub(super) fn chat_reply_content(&self, c: Tid) -> osis::Result<Content> {
        let mut blocks = Vec::new();
        if let Some(r) = self.compose.reply {
            let what = match osis_chat::find(&self.data.db, c, &r)? {
                Some(m) => format!("Replying to {}", chat::quote(&m)),
                None => format!("Replying to {r}"),
            };
            blocks.push(Block::Line(what));
            blocks.push(Block::Chips(vec![ChipM::action(Icon::Back, "Don't reply", Act::Reply(None))]));
        }
        Ok(Content { blocks })
    }

    /// One message: who and when, what it answers, its text, a reply button.
    pub(super) fn message_widget(&mut self, l: &Line) -> NewWidget<dyn Widget> {
        let look = self.look.clone();
        let mut head = format!("{} · {}", l.who, when(l.time));
        if l.edited {
            head.push_str(" · edited");
        }
        let mut col = Flex::column().cross_axis_alignment(CrossAxisAlignment::Fill).with_gap(Length::px(look.sp(4.0))).with_child(style::prose(&look, &head, Text::Small));
        if let Some((_, to)) = &l.reply_to {
            col = col.with_child(style::prose(&look, &format!("↩ {to}"), Text::Muted));
        }
        col = col.with_child(style::prose(&look, &l.text, Text::Body));
        let reply = NewWidget::new(osis_kit::widgets::Chip::new("Reply", None, osis_kit::widgets::ChipMark::Icon(Icon::Back), look.clone()).flat(true));
        let row = Flex::row().with_flex_spacer(1.0).with_child(self.act(reply, Act::Reply(Some(l.id))));
        col = col.with_child(NewWidget::new(row));
        let kind = if l.mine { PanelKind::Highlight } else { PanelKind::Inset };
        NewWidget::new(Panel::new(NewWidget::new(col), look, kind, (10.0, 12.0))).erased()
    }

    /// The open chat's watch, renewed when it ends.
    pub(super) fn watch_chat(&mut self, open: Option<Tid>) -> osis::Result<()> {
        if self.chat_sub.as_ref().map(|s| s.0) == open {
            return Ok(());
        }
        self.chat_sub = None;
        if let Some(c) = open {
            let mb = self.mb.clone();
            let subs = osis_chat::watch(&self.data.db, c, move |_, e| {
                mb.post(if matches!(e, osis_chat::Event::Ended(_)) { Msg::ChatEnded } else { Msg::Changed });
            })?;
            self.chat_sub = Some((c, subs));
        }
        Ok(())
    }

    /// Scrolls the timeline to the newest (the portal clamps to its content).
    pub(super) fn scroll_end(&mut self, ctx: &mut DriverCtx<'_, '_>) {
        let root = ctx.render_root(self.window);
        if root.get_widget_with_tag(CHAT_SCROLL).is_some() {
            root.edit_widget_with_tag(CHAT_SCROLL, |mut p| {
                Portal::set_viewport_pos(&mut p, Point::new(0.0, 1e9));
            });
        }
    }

    /// Sends the composer's message to `c` and empties it.
    pub(super) fn send(&mut self, ctx: &mut DriverCtx<'_, '_>, c: Tid) -> osis::Result<()> {
        self.save_name()?;
        chat::send(&self.data.db, c, &self.compose.subject, &self.compose.text, self.compose.reply)?;
        self.compose.subject.clear();
        self.compose.text.clear();
        self.compose.reply = None;
        let root = ctx.render_root(self.window);
        for i in [Input::Subject, Input::Text] {
            if let Some(id) = self.compose.id_of(i)
                && root.has_widget(id)
            {
                root.edit_widget(id, |mut w| TextArea::reset_text(&mut w.downcast::<TextArea<true>>(), ""));
            }
        }
        Ok(())
    }

    /// The typed name, saved if it changed.
    fn save_name(&mut self) -> osis::Result<()> {
        let Some(n) = self.compose.name.take() else { return Ok(()) };
        if chat::my_name(&self.data.db)?.unwrap_or_default() != n.trim() {
            chat::set_name(&self.data.db, &n)?;
        }
        Ok(())
    }

    pub(super) fn chat_typed(&mut self, ctx: &mut DriverCtx<'_, '_>, id: WidgetId, a: TextAction) {
        let Some(i) = self.compose.ids.get(&id).copied() else { return };
        let (text, entered) = match a {
            TextAction::Changed(t) => (t, false),
            TextAction::Entered(t) => (t, true),
        };
        match i {
            Input::Join => self.compose.join = text,
            Input::Name => self.compose.name = Some(text),
            Input::Subject => self.compose.subject = text,
            Input::Text => self.compose.text = text,
        }
        if !entered {
            return;
        }
        match i {
            Input::Join => self.start_join(ctx),
            Input::Name => {
                if let Err(e) = self.save_name() {
                    self.status(ctx, format!("error: {e}"));
                }
            }
            Input::Subject => {
                if let Some(t) = self.compose.text_id() {
                    ctx.render_root(self.window).focus_on(Some(t));
                }
            }
            Input::Text => {
                if let Some(c) = self.chat {
                    self.press(ctx, Act::Send(c));
                }
            }
        }
    }

    pub(super) fn chat_blur(&mut self, ctx: &mut DriverCtx<'_, '_>, input: WidgetId) {
        if self.compose.ids.get(&input) == Some(&Input::Name)
            && let Err(e) = self.save_name()
        {
            self.status(ctx, format!("error: {e}"));
        }
    }

    /// Redeems the typed link off the UI thread (it waits for the link's host).
    fn start_join(&mut self, ctx: &mut DriverCtx<'_, '_>) {
        let link = self.compose.join.trim().to_string();
        if link.is_empty() || self.compose.joining {
            return;
        }
        self.compose.joining = true;
        self.status(ctx, "joining…".into());
        let (db, mb) = (self.data.db.clone(), self.mb.clone());
        std::thread::spawn(move || {
            let r = chat::join(&db, &link).map_err(|e| e.to_string());
            mb.post(Msg::Joined(r));
        });
    }

    /// A join ended: open the chat, or say why not.
    pub(super) fn joined(&mut self, ctx: &mut DriverCtx<'_, '_>, r: Result<Tid, String>) {
        self.compose.joining = false;
        match r {
            Ok(c) => {
                self.compose.join.clear();
                self.compose.reply = None;
                self.chat = Some(c);
                self.diag = None;
            }
            Err(e) => {
                self.diag = Some(format!("join failed: {e}"));
                self.status(ctx, format!("join failed: {e}"));
            }
        }
    }
}
