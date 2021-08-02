// Rust support for running sq-subplot.md scenarios.

use subplotlib::steplibrary::runcmd::Runcmd;

use std::path::Path;

#[step]
#[context(Runcmd)]
fn install_sq(context: &ScenarioContext) {
    // The SQ_DIR variable can be set to test an installed sq rather
    // than the one built from the source tree.
    if let Some(bindir) = std::env::var_os("SQ_DIR") {
        println!("Found SQ_DIR environment variable, using that");
        context.with_mut(
            |rc: &mut Runcmd| {
                rc.prepend_to_path(bindir);
                Ok(())
            },
            false,
        )?;
    } else {
        let target_exe = env!("CARGO_BIN_EXE_sq");
        let target_path = Path::new(target_exe);
        let target_path = target_path.parent().ok_or("No parent?")?;

        context.with_mut(
            |context: &mut Runcmd| {
                context.prepend_to_path(target_path);
                Ok(())
            },
            false,
        )?;
    }
}
