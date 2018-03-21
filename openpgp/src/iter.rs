use std::slice;
use std::vec;

use PacketCommon;
use Packet;
use Container;
use Message;
use PacketIter;
use PacketPathIter;

#[cfg(test)]
use std::path::PathBuf;

#[cfg(test)]
fn path_to(artifact: &str) -> PathBuf {
    [env!("CARGO_MANIFEST_DIR"), "tests", "data", "messages", artifact]
        .iter().collect()
}

impl PacketCommon {
    /// Returns an iterator over all of the packet's descendants, in
    /// depth-first order.
    pub fn descendants(&self) -> PacketIter {
        return PacketIter {
            children: if let Some(ref container) = self.children {
                container.packets.iter()
            } else {
                let empty_packet_slice : &[Packet] = &[][..];
                empty_packet_slice.iter()
            },
            child: None,
            grandchildren: None,
            depth: 0,
        }
    }
}

impl Container {
    /// Returns an iterator over the packet's descendants.  The
    /// descendants are visited in depth-first order.
    pub fn descendants(&self) -> PacketIter {
        return PacketIter {
            // Iterate over each packet in the message.
            children: self.children(),
            child: None,
            grandchildren: None,
            depth: 0,
        };
    }

    /// Returns an iterator over the packet's immediate children.
    pub fn children<'a>(&'a self) -> slice::Iter<'a, Packet> {
        self.packets.iter()
    }

    /// Returns an `IntoIter` over the packet's immediate children.
    pub fn into_children(self) -> vec::IntoIter<Packet> {
        self.packets.into_iter()
    }
}

impl Message {
    /// Turns a vector of [`Packet`s] into a `Message`.
    ///
    /// This is a simple wrapper function; it does not process the
    /// packets in any way.
    ///
    ///   [`Packet`s]: struct.Packet.html
    pub fn from_packets(p: Vec<Packet>) -> Self {
        Message { top_level: Container { packets: p } }
    }

    /// Turns a  [`Packet`] into a `Message`.
    ///
    /// This is a simple wrapper function; it does not process the
    /// packets in any way.
    ///
    ///   [`Packet`]: struct.Packet.html
    pub fn from_packet(p: Packet) -> Self {
        let mut top_level = Vec::with_capacity(1);
        top_level.push(p);
        Self::from_packets(top_level)
    }

    /// Returns an iterator over all of the packet's descendants, in
    /// depth-first order.
    pub fn descendants(&self) -> PacketIter {
        self.top_level.descendants()
    }

    /// Returns an iterator over the top-level packets.
    pub fn children<'a>(&'a self) -> slice::Iter<'a, Packet> {
        self.top_level.children()
    }

    /// Returns an `IntoIter` over the top-level packets.
    pub fn into_children(self) -> vec::IntoIter<Packet> {
        self.top_level.into_children()
    }
}

impl<'a> Iterator for PacketIter<'a> {
    type Item = &'a Packet;

    fn next(&mut self) -> Option<Self::Item> {
        // If we don't have a grandchild iterator (self.grandchildren
        // is None), then we are just starting, and we need to get the
        // next child.
        if let Some(ref mut grandchildren) = self.grandchildren {
            let grandchild = grandchildren.next();
            // If the grandchild iterator is exhausted (grandchild is
            // None), then we need the next child.
            if grandchild.is_some() {
                self.depth = grandchildren.depth + 1;
                return grandchild;
            }
        }

        // Get the next child and the iterator for its children.
        self.child = self.children.next();
        if let Some(child) = self.child {
            self.grandchildren = Some(Box::new(child.descendants()));
        }

        // First return the child itself.  Subsequent calls will
        // return its grandchildren.
        self.depth = 0;
        return self.child;
    }
}

impl<'a> PacketIter<'a> {
    /// Extends a `PacketIter` to also return each packet's path.
    ///
    /// This is similar to `enumerate`, but instead of counting, this
    /// returns each packet's path in addition to a reference to the
    /// packet.
    pub fn paths(self) -> PacketPathIter<'a> {
        PacketPathIter {
            iter: self,
            path: None,
        }
    }
}

impl<'a> Iterator for PacketPathIter<'a> {
    type Item = (Vec<usize>, &'a Packet);

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(packet) = self.iter.next() {
            if self.path.is_none() {
                // Init.
                let mut path = Vec::with_capacity(4);
                path.push(0);
                self.path = Some(path);
            } else {
                let mut path = self.path.take().unwrap();
                let old_depth = path.len() - 1;

                let depth = self.iter.depth;
                if old_depth > depth {
                    // We popped.
                    path.truncate(depth + 1);
                    path[depth] += 1;
                } else if old_depth == depth {
                    // Sibling.
                    path[old_depth] += 1;
                } else if old_depth + 1 == depth {
                    // Recursion.
                    path.push(0);
                }
                self.path = Some(path);
            }
            Some((self.path.as_ref().unwrap().clone(), packet))
        } else {
            None
        }
    }
}

// Tests the `paths`() iter and `path_ref`().
#[test]
fn packet_path_iter() {
    fn paths(iter: slice::Iter<Packet>) -> Vec<Vec<usize>> {
        let mut lpaths : Vec<Vec<usize>> = Vec::new();
        for (i, packet) in iter.enumerate() {
            let mut v = Vec::new();
            v.push(i);
            lpaths.push(v);

            if let Some(ref children) = packet.children {
                for mut path in paths(children.packets.iter()).into_iter() {
                    path.insert(0, i);
                    lpaths.push(path);
                }
            }
        }
        lpaths
    }

    for i in 1..5 {
        let m = Message::from_file(
            path_to(&format!("recursive-{}.gpg", i)[..])).unwrap();

        let mut paths1 : Vec<Vec<usize>> = Vec::new();
        for path in paths(m.children()).iter() {
            paths1.push(path.clone());
        }

        let mut paths2 : Vec<Vec<usize>> = Vec::new();
        for (path, packet) in m.descendants().paths() {
            assert_eq!(Some(packet), m.path_ref(&path[..]));
            paths2.push(path);
        }

        if paths1 != paths2 {
            eprintln!("Message:");
            m.pretty_print();

            eprintln!("Expected paths:");
            for p in paths1 {
                eprintln!("  {:?}", p);
            }

            eprintln!("Got paths:");
            for p in paths2 {
                eprintln!("  {:?}", p);
            }

            panic!("Something is broken.  Don't panic.");
        }
    }
}
