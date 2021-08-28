#[cfg(test)]
pub(crate) mod tests {
    use crate::prelude::*;
    use std::{fs::{File}, io::{Cursor, Read}};
    use ed25519_dalek as esdalek;
    use rand::rngs::OsRng;

    const KEYPAIR: &str = "test_data/pair.pub";
    const SIGNED_TARGET: &str = "test_data/signed/target.vach";
    const SIMPLE_TARGET: &str = "test_data/simple/target.vach";

    #[test]
    pub(crate) fn defaults() {
        let _header_config = HeaderConfig::new();
        let _header = Header::default();
        let _registry = Registry::empty();
        let _registry_entry = RegistryEntry::empty();
        let _resource = Resource::empty();
        let _leaf = Leaf::empty();
        let _leaf_config = LeafConfig::default();
        let _builder:Builder<Cursor<Vec<u8>>> = Builder::default();
        let _builder_config = BuilderConfig::default();
        let _flags = FlagType::empty();
    }

    #[test]
    pub(crate) fn header_config() -> anyhow::Result<()> {
        let config = HeaderConfig::from(*b"VfACH", 0, None);
        let mut file = File::open("test_data/simple/target.vach")?;
        format!("{}", &config);

        let mut _header = Header::from(&mut file)?;
        format!("{}", _header);

        Archive::validate(&mut file, &config)?;
        Ok(())
    }

    #[test]
    pub fn loader_no_signature() -> anyhow::Result<()> {
        let target = File::open(SIMPLE_TARGET)?;
        let mut archive = Archive::from(target)?;
        let resource = archive.fetch("song")?;
        println!("{}", std::str::from_utf8(resource.data.as_slice())?);
        Ok(())
    }

    #[test]
    pub(crate) fn writer_no_signature() -> anyhow::Result<()>{
        let mut builder = Builder::default();
        let build_config = BuilderConfig::default();
        builder.add_with_config(
            File::open("test_data/poem.txt")?,
            &LeafConfig::default()
                .compress(false)
                .version(12)
                .id(&"poem")
        )?;
        builder.add(File::open("test_data/song.txt")?, "song")?;

        let mut target = File::create(SIMPLE_TARGET)?;
        builder.write(&mut target, &build_config)?;
        Ok(())
    }

    #[test]
    pub fn loader_with_signature() -> anyhow::Result<()> {
        let mut target = File::open(SIGNED_TARGET)?;
        
        // Load keypair
        let mut keypair_bytes = [4; crate::KEYPAIR_LENGTH];
        File::open(KEYPAIR)?.read(&mut keypair_bytes)?;
        let keypair = esdalek::Keypair::from_bytes(&keypair_bytes)?;
        let config = &HeaderConfig::default().key(Some(keypair.public));

        Archive::validate(&mut target, &config)?;
        Ok(())
    }

    #[test]
    pub(crate) fn writer_with_signature() -> anyhow::Result<()>{
        let mut builder = Builder::default();
        let mut build_config = BuilderConfig::default();

        let mut keypair_bytes = [4; crate::KEYPAIR_LENGTH];
        File::open(KEYPAIR)?.read(&mut keypair_bytes)?;
        build_config.keypair = Some(esdalek::Keypair::from_bytes(&keypair_bytes)?);

        builder.add_with_config(
            File::open("test_data/poem.txt")?,
            &LeafConfig::default().compress(false).version(12).id(&"poem")
        )?;
        builder.add(File::open("test_data/song.txt")?, "song")?;

        let mut target = File::create(SIGNED_TARGET)?;
        builder.write(&mut target, &build_config)?;
        Ok(())
    }

    #[test]
    pub fn gen_keypair() -> anyhow::Result<()> {
        // NOTE: regenerating new keys will break some tests
        let regenerate = true;

        if regenerate {
            let mut rng = OsRng;
            let keypair = esdalek::Keypair::generate(&mut rng);
    
            std::fs::write( KEYPAIR, &keypair.to_bytes())?;
        };

        Ok(())
    }

    #[test]
    pub(crate) fn esdalek_test() -> anyhow::Result<()>{
        println!("Bytes per esdalek::Signature: {}", esdalek::SIGNATURE_LENGTH);
        Ok(())
    }
}
