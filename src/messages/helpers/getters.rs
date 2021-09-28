macro_rules! create_fallback_getter {
    ($primary_field:ident, $fallback_field:ident, $field_name:ident, $field_type:ident) => {
        paste::item! {
            #[doc = concat!(
                "Gets `",
                stringify!($field_name),
                "` header value from either `",
                stringify!($primary_field),
                "` or from `",
                stringify!($fallback_field),
                "`.\n\n",
                "Will default to `None` if not set in any of them."
            )]
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
