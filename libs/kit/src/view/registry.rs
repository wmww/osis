//! What a Data knows: its facets and view types. Only this list names them; kit's and an app's
//! both register here.

use super::Facet;
use crate::views::ViewType;

/// The facets and view types of a Data.
pub struct Registry {
    pub facets: Vec<&'static dyn Facet>,
    pub views: Vec<&'static ViewType>,
}

impl Registry {
    /// Kit's facets of core aspects and its generic view types.
    pub fn kit() -> Registry {
        Registry { facets: crate::facets::kit().to_vec(), views: crate::views::kit().to_vec() }
    }

    pub fn facet(&self, id: &str) -> Option<&'static dyn Facet> {
        self.facets.iter().copied().find(|f| f.id() == id)
    }

    pub fn view(&self, id: &str) -> Option<&'static ViewType> {
        self.views.iter().copied().find(|v| v.id == id)
    }

    /// Inserts a facet before `before` (summary order).
    pub fn with_facet_before(mut self, before: &str, f: &'static dyn Facet) -> Registry {
        let i = self.facets.iter().position(|x| x.id() == before).unwrap_or(self.facets.len());
        self.facets.insert(i, f);
        self
    }

    /// Inserts a content view before `before` (fit ties go to the earlier).
    pub fn with_view_before(mut self, before: &str, v: &'static ViewType) -> Registry {
        let i = self.views.iter().position(|x| x.id == before).unwrap_or(self.views.len());
        self.views.insert(i, v);
        self
    }
}
