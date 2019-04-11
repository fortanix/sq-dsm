// Flattens an iterator of `(bool, String)s`.  Adds `sep` in front of
// each string if element.0 is true.
pub(crate) fn strings_flatten2_into<I, S>(s: String, i: I, sep: S) -> String
    where I: Iterator<Item=(bool, String)>,
          S: AsRef<str>
{
    let sep = sep.as_ref();

    i.fold(s,
           |mut v, (add, mut e)| {
               if add {
                   v.push_str(sep);
               }

               v.push_str(&mut e);
               v
           })
}

// Like strings_flatten2_into, but uses an empty vector.
pub(crate) fn strings_flatten2<I, S>(i: I, sep: S) -> String
    where I: Iterator<Item=(bool, String)>,
          S: AsRef<str>
{
    strings_flatten2_into(String::new(), i, sep)
}

// Flattens an iterator of `(String)s` and appends the result to `s`.
//
// `sep` is inserted between each element.  `sep` is not added in
// front of the first element even if s is not empty.
pub(crate) fn strings_flatten_into<I, S>(s: String, i: I, sep: S) -> String
    where I: Iterator<Item=String>,
          S: AsRef<str>
{
    let sep = sep.as_ref();

    i.enumerate()
        .fold(s,
              |mut v, (i, mut e)| {
                  if i > 0 {
                      v.push_str(sep);
                  }

                  v.push_str(&mut e);
                  v
              })
}

// Like strings_flatten_into, but uses an empty vector.
pub(crate) fn strings_flatten<I, S>(i: I, sep: S) -> String
    where I: Iterator<Item=String>,
          S: AsRef<str>
{
    strings_flatten_into(String::new(), i, sep)
}

