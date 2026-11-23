//! Masonry tags (patches/masonry_core): removing a tagged widget frees its tag, so a new widget can
//! take it and lookups never reach the removed one.
use osis_kit::masonry::app::RenderRoot;
use osis_kit::masonry::core::{NewWidget, WidgetTag};
use osis_kit::masonry::widgets::{Flex, Label};

const NOTE: WidgetTag<Label> = WidgetTag::new("note");

fn root() -> RenderRoot {
    crate::render_root(NewWidget::new(Flex::column()).erased(), (200, 200), 1.0).0
}

fn add(root: &mut RenderRoot, text: &str) {
    root.edit_base_layer(|mut w| Flex::add_child(&mut w.downcast::<Flex>(), NewWidget::new_with_tag(Label::new(text), NOTE)));
}

fn remove(root: &mut RenderRoot) {
    root.edit_base_layer(|mut w| Flex::remove_child(&mut w.downcast::<Flex>(), 0));
}

fn tagged_text(root: &RenderRoot) -> Option<String> {
    root.get_widget_with_tag(NOTE).map(|w| w.inner().text().to_string())
}

#[test]
fn removed_tag_is_free_again() {
    let mut root = root();
    add(&mut root, "first");
    let first = root.get_widget_with_tag(NOTE).unwrap().id();
    remove(&mut root);
    assert!(tagged_text(&root).is_none());
    add(&mut root, "second");
    assert_eq!(tagged_text(&root).as_deref(), Some("second"));
    assert_ne!(root.get_widget_with_tag(NOTE).unwrap().id(), first);
    root.edit_widget_with_tag(NOTE, |mut l| Label::set_text(&mut l, "third"));
    assert_eq!(tagged_text(&root).as_deref(), Some("third"));
}

/// A tagged widget inside a removed subtree frees its tag too.
#[test]
fn removed_subtree_frees_tags() {
    let mut root = root();
    root.edit_base_layer(|mut w| {
        Flex::add_child(&mut w.downcast::<Flex>(), NewWidget::new(Flex::row().with_child(NewWidget::new_with_tag(Label::new("deep"), NOTE))))
    });
    assert_eq!(tagged_text(&root).as_deref(), Some("deep"));
    remove(&mut root);
    assert!(tagged_text(&root).is_none());
    add(&mut root, "again");
    assert_eq!(tagged_text(&root).as_deref(), Some("again"));
}

/// Replacing a subtree in one edit (as the app rebuilds a screen or slot: the old child out, a
/// new one with the same tags in) leaves the tag on the new widget.
#[test]
fn replaced_in_one_edit() {
    use osis_kit::masonry::widgets::SizedBox;
    let mut root = root();
    root.edit_base_layer(|mut w| Flex::add_child(&mut w.downcast::<Flex>(), NewWidget::new(SizedBox::new(NewWidget::new_with_tag(Label::new("old"), NOTE)))));
    for text in ["new", "newer"] {
        root.edit_base_layer(|mut w| {
            let mut f = w.downcast::<Flex>();
            let mut b = Flex::child_mut(&mut f, 0).unwrap();
            SizedBox::set_child(&mut b.downcast::<SizedBox>(), NewWidget::new_with_tag(Label::new(text), NOTE));
        });
        assert_eq!(tagged_text(&root).as_deref(), Some(text));
    }
    root.edit_base_layer(|mut w| {
        let mut f = w.downcast::<Flex>();
        Flex::remove_child(&mut f, 0);
        Flex::add_child(&mut f, NewWidget::new_with_tag(Label::new("swapped"), NOTE));
    });
    assert_eq!(tagged_text(&root).as_deref(), Some("swapped"));
}
