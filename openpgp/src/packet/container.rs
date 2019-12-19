macro_rules! impl_container_forwards {
    ($typ:ident) => {
        /// This packet implements the container interface.
        ///
        /// Container packets can contain other packets, unprocessed
        /// data, or both.
        impl $typ {
            /// Returns a reference to the container.
            pub(crate) fn container_ref(&self) -> &packet::Container {
                &self.container
            }

            /// Returns a mutable reference to the container.
            pub(crate) fn container_mut(&mut self) -> &mut packet::Container {
                &mut self.container
            }

            /// Gets a reference to the this packet's body.
            pub fn body(&self) -> Option<&[u8]> {
                self.container.body()
            }

            /// Gets a mutable reference to the this packet's body.
            pub fn body_mut(&mut self) -> Option<&mut Vec<u8>> {
                self.container.body_mut()
            }

            /// Sets the this packet's body.
            pub fn set_body(&mut self, data: Vec<u8>) -> Vec<u8> {
                self.container.set_body(data)
            }

            /// Returns an iterator over the packet's immediate children.
            pub fn children<'a>(&'a self) -> impl Iterator<Item = &'a Packet> {
                self.container.children()
            }

            /// Returns an iterator over all of the packet's descendants, in
            /// depth-first order.
            pub fn descendants(&self) -> super::Iter {
                self.container.descendants()
            }
        }
    };
}
