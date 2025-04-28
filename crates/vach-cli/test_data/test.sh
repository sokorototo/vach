#! /usr/bin/sh

set -xe

# # Variables
EXCLUDE=test.sh
ARTIFACTS="keypair.sk keypair.pk keypair.kp signed.vach custom.vach encrypted.vach"
CMD="cargo run -qr --"

# # Delete any previous artifacts
rm -f $ARTIFACTS

# # Prelude
echo "Starting vach-cli tests..."

# # Cargo tests
cargo build --release

# # Create simple archive with simple input, no compression only signatures
$CMD pack --output signed.vach --directory-r ./ --compress-mode detect --compress-algo brotli --hash --exclude $EXCLUDE

# # Split the resulting keypair
$CMD list -i signed.vach

# # Generate a compressed archive
$CMD pack -o custom.vach -i GamerProfile.xml -x $EXCLUDE
$CMD list -i custom.vach

# # Generate an encrypted, signed and compressed archive
$CMD pack -ea -o encrypted.vach -d lolcalt -c always -s keypair.sk
$CMD list -i encrypted.vach

# Unpack the encrypted archive
$CMD unpack -i encrypted.vach -k keypair.kp

# # Delete any previous artifacts
rm -f $ARTIFACTS
