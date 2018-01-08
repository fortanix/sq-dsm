use std::fmt;

use Packet;
use Message;

impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Message")
            .field("packets", &self.top_level.packets)
            .finish()
    }
}

impl Message {
    /// Pretty prints the message to stderr.
    ///
    /// This function is primarily intended for debugging purposes.
    pub fn pretty_print(&self) {
        self.top_level.pretty_print(0);
    }

    /// Returns the packet at the location described by `pathspec`.
    ///
    /// `pathspec` is a slice of the form `[ 0, 1, 2 ]`.  Each element
    /// is the index of packet in a container.  Thus, the previous
    /// path specification means: return the third child of the second
    /// child of the first top-level packet.  In other words, the
    /// starred packet in the following tree:
    ///
    /// ```text
    ///           Message
    ///        /     |     \
    ///       0      1      2  ...
    ///     /   \
    ///    /     \
    ///  0         1  ...
    ///        /   |   \  ...
    ///       0    1    2
    ///                 *
    /// ```
    ///
    /// And, `[ 10 ]` means return the 11th top-level packet.
    ///
    /// Note: there is no packet at the root.  Thus, the path `[]`
    /// returns None.
    pub fn path_ref(&self, pathspec: &[usize]) -> Option<&Packet> {
        let mut packet : Option<&Packet> = None;

        let mut cont = Some(&self.top_level);
        for i in pathspec {
            if let Some(ref c) = cont.take() {
                if *i < c.packets.len() {
                    let p = &c.packets[*i];
                    packet = Some(p);
                    cont = p.children.as_ref();
                    continue;
                }
            }

            return None;
        }
        return packet;
    }
}
