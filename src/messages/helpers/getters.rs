macro_rules! create_fallback_getter {
    ($primary_field:ident, $fallback_field:ident, $field_name:ident, $field_type:ident) => {
        paste::item! {
            pub fn [< get_ $field_name >](&self) -> Option<$field_type> {
                if let Some(value) = &self.$primary_field {
                    if let Some(value) = &value.$field_name {
                        return Some(value.clone());
                    }
                }
                if let Some(value) = &self.$fallback_field {
                    if let Some(value) = &value.$field_name {
                        return Some(value.clone());
                    }
                }
                None
            }
        }
    };
}
pub(crate) use create_fallback_getter;
