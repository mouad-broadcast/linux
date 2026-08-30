// ============================================
// YOUR EXISTING IMPORTS (Keep these!)
// ============================================
use memflow::plugins::{ConnectorArgs, Inventory, OsArgs};
use memflow::prelude::v1::*;

// YOUR EXISTING MODULES (Keep these!)
mod discovery;
mod pe;

// ============================================
// NEW MODULES (ADD THESE)
// ============================================
mod decrypt;
mod encrypted_ptr;
mod memory_adapter;

// ============================================
// NEW IMPORTS (ADD THESE)
// ============================================
use decrypt::StateDecrypt;
use encrypted_ptr::EncryptedPtr64;
use memory_adapter::{GameMemoryReader, MemoryReader};
use std::sync::Arc;




// --------------------------------------------------
// Connection
// --------------------------------------------------

const CONNECTOR: &str = "kvm";
const OS: &str = "win32";

const TARGET_PID: u32 = 5184;

// Put your KVM connector PID here.
const CONNECTOR_PID: u32 = 0;

// --------------------------------------------------
// Offsets
// --------------------------------------------------

pub const UWORLD: u64 = 0x12284408;

pub const GAME_INSTANCE: u64 = 0x8F8;
pub const LOCAL_PLAYER: u64 = 0xF0;
pub const PLAYER_CONTROLLER: u64 = 0x38;
pub const ACKNOWLEDGED_PAWN: u64 = 0x4B8;

pub const ROOT_COMPONENT: u64 = 0x1C0;
pub const ROOT_COMPONENT_POS: u64 = 0x250;

pub const CHARACTER_NAME: u64 = 0x1A30;

// --------------------------------------------------
// Read helper
// --------------------------------------------------

fn read_ptr(
process: &mut impl MemoryView,
address: Address,
label: &str,
) -> Option<u64> {
match process.read::<u64>(address) {
Ok(value) => {
println!(
"{:<22} [{:#x}] -> {:#x}",
label,
address,
value
);

 
        if value == 0 {
            println!("  {} = NULL", label);
            None
        } else {
            Some(value)
        }
    }

    Err(error) => {
        println!(
            "{:<22} [{:#x}] -> READ FAILED: {}",
            label,
            address,
            error
        );

        None
    }
}
 

}

// --------------------------------------------------
// Main
// --------------------------------------------------

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
println!("Memory Debugger");
println!("================");

// --------------------------------------------------
// Connect
// --------------------------------------------------

let mut inventory = Inventory::scan();

let connector_args: ConnectorArgs =
    format!(":pid={}:",
            CONNECTOR_PID)
        .parse()?;

let os_args: OsArgs = "".parse()?;

let mut os = inventory
    .builder()
    .connector(CONNECTOR)
    .args(connector_args)
    .os(OS)
    .args(os_args)
    .build()?;

println!("Connected to Windows guest.");

// --------------------------------------------------
// Find process ONLY by PID
// --------------------------------------------------

let processes = os.process_info_list()?;

let process_info =
    match processes.iter().find(|p| p.pid == TARGET_PID) {
        Some(p) => p,

        None => {
            println!(
                "Process not found with PID {}.",
                TARGET_PID
            );

            return Ok(());
        }
    };

println!();
println!("Target:");
println!("  PID  : {}", process_info.pid);
println!("  State: {:?}", process_info.state);

// --------------------------------------------------
// Open process
// --------------------------------------------------

let mut process =
    os.process_by_pid(process_info.pid)?;

// --------------------------------------------------
// Module
// --------------------------------------------------

let module =
    process.module_by_name(&process_info.name)?;

println!();
println!("Module:");
println!("  Base : {:#x}", module.base);
println!("  Size : {:#x}", module.size);

// HNA MAIN

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // --- YOUR EXISTING MEMFLOW SETUP ---
    let args = ConnectorArgs::parse();
    let inventory = Inventory::scan();
    let connector = inventory.create_connector(&args)?;
    let os = inventory.create_os(&OsArgs::new(connector, None))?;
    
    // --- YOUR EXISTING GAME DISCOVERY ---
    // Use your discovery module to find the game
    let pid = discovery::find_pid()?; // Your existing function
    let game_base = pe::get_base_address()?; // Your existing function
    
    // Get the process from memflow
    let process = os.process_by_pid(pid)?;
    let process = Arc::new(process);
    
    // --- YOUR EXISTING GAME INFO GATHERING ---
    // ... your code that gets lots of game info and values
    // This stays exactly as it was!
    
    // ============================================
    // NEW: DECRYPTION INITIALIZATION
    // ============================================
    let memory_reader = GameMemoryReader::new(pid, game_base, process.clone());
    let decryptor = StateDecrypt::new(game_base, &memory_reader)?;
    println!("✅ Decryptor initialized!");
    
    // ============================================
    // NEW: USE DECRYPTION ON YOUR DATA
    // ============================================
    // Example: If you have an encrypted address from your game reading
    // Replace 0xDEADBEEF with an actual encrypted address you found
    let encrypted_address = 0xDEADBEEF;
    let decrypted = unsafe { decryptor.decrypt(encrypted_address) };
    println!("🔓 Decrypted: {:#X} -> {:#X}", encrypted_address, decrypted);
    
    // Example: Using EncryptedPtr64
    let encrypted_ptr = EncryptedPtr64::<u64>::new(encrypted_address);
    if let Some(value) = encrypted_ptr.read_value(&memory_reader, &decryptor)? {
        println!("📦 Value: {}", value);
    }
    
    // ============================================
    // YOUR EXISTING CODE CONTINUES
    // ============================================
    // ... rest of your existing main logic
    
    Ok(())
}



// --------------------------------------------------
// PE inspection
// --------------------------------------------------

println!();
println!("================================");
println!("PE INSPECTION");
println!("================================");

let pe_info =
    match pe::inspect_pe(
        &mut process,
        module.base.into(),
    ) {
        Ok(info) => {
            println!("PE:");
            println!(
                "  Machine        : {:#x}",
                info.machine
            );
            println!(
                "  ImageBase      : {:#x}",
                info.image_base
            );
            println!(
                "  EntryPoint RVA : {:#x}",
                info.entry_point
            );
            println!(
                "  SizeOfImage    : {:#x}",
                info.size_of_image
            );
            println!(
                "  SizeOfHeaders  : {:#x}",
                info.size_of_headers
            );

            println!();
            println!("Sections:");

            for section in &info.sections {
                println!(
                    "  {:<8} RVA={:#010x} VirtualSize={:#010x} RawSize={:#010x} Characteristics={:#010x}",
                    section.name,
                    section.virtual_address,
                    section.virtual_size,
                    section.raw_size,
                    section.characteristics
                );
            }

            info
        }

        Err(error) => {
            println!("PE inspection FAILED:");
            println!("  {}", error);
            return Ok(());
        }
    };




println!();
println!("================================");
println!("KNOWN GLOBAL DIAGNOSTIC");
println!("================================");

let uworld_global = module.base + UWORLD;

println!(
    "Module base        : {:#018x}",
    module.base.to_umem()
);

println!(
    "UWorld RVA         : {:#x}",
    UWORLD
);

println!(
    "UWorld global      : {:#018x}",
    uworld_global.to_umem()
);

match process.read::<u64>(uworld_global.into()) {
    Ok(value) => {
        println!(
            "UWorld raw qword   : {:#018x}",
            value
        );
    }

    Err(error) => {
        println!(
            "UWorld read FAILED : {}",
            error
        );
    }
}

println!();
println!("UWorld global bytes");
println!("-------------------");

for i in 0..256u64 {
    let address = uworld_global + i;

    if i % 16 == 0 {
        print!("{:#06x}: ", i);
    }

    match process.read::<u8>(address.into()) {
        Ok(byte) => {
            print!("{:02x} ", byte);
        }
        Err(_) => {
            print!("?? ");
        }
    }

    if (i + 1) % 16 == 0 {
        println!();
    }
}
println!();
println!("================================");
println!("PATTERN QUICK TEST");
println!("================================");

let test_pattern =
    "2e ab df d0 ? ? 6c 20 ? ? ? ? b9 01 00 00";

match discovery::find_pattern(
    &mut process,
    uworld_global.to_umem(),
    0x100,
    test_pattern,
)? {
    Some(address) => {
        println!("PATTERN MATCH");
        println!("  Pattern : {}", test_pattern);
        println!("  Address : {:#018x}", address);
        println!(
            "  Offset  : {:#x}",
            address - uworld_global.to_umem()
        );
    }

    None => {
        println!("PATTERN NOT FOUND");
    }
}

// --------------------------------------------------
// Valthrun-inspired signature test
// --------------------------------------------------

println!();
println!("================================");
println!("VALTHRUN-INSPIRED SIGNATURE TEST");
println!("================================");

let signature_start = uworld_global.to_umem();
let signature_size = 0x100usize;

// Use bytes that we already know exist at the test location.
// Wildcards model Valthrun's ByteSequencePattern behavior.
let signature_pattern = "2e ab ?? d0 8d 0d ?? 20";

println!("  Start   : {:#018x}", signature_start);
println!("  Size    : {:#x}", signature_size);
println!("  Pattern : {}", signature_pattern);

match discovery::find_pattern(
    &mut process,
    signature_start,
    signature_size,
    signature_pattern,
)? {
    Some(address) => {
        println!("  Match   : {:#018x}", address);
        println!(
            "  Offset  : {:#x}",
            address - signature_start
        );
        println!("  Result  : PASS");
    }

    None => {
        println!("  Match   : NOT FOUND");
        println!("  Result  : FAIL");
    }
}
// --------------------------------------------------
// Valthrun-inspired signature resolution test
// --------------------------------------------------

println!();
println!("================================");
println!("SIGNATURE RESOLUTION TEST");
println!("================================");

let resolution_pattern =
    "2e ab ?? d0 8d 0d ?? 20";

let resolution_start =
    uworld_global.to_umem();

let resolution_size =
    0x100usize;

let resolution_offset =
    0x08u64;

println!(
    "  Start   : {:#018x}",
    resolution_start
);

println!(
    "  Pattern : {}",
    resolution_pattern
);

println!(
    "  Offset  : {:#x}",
    resolution_offset
);

match discovery::test_signature_resolution(
    &mut process,
    resolution_start,
    resolution_size,
    resolution_pattern,
    resolution_offset,
)? {
    Some(value) => {
        println!(
            "  Value   : {:#018x}",
            value
        );

        println!("  Result  : PASS");
    }

    None => {
        println!("  Match   : NOT FOUND");
        println!("  Result  : FAIL");
    }
}
// --------------------------------------------------
// Private-game live offset diagnostics
// --------------------------------------------------

println!();
println!("================================");
println!("PRIVATE GAME OFFSET TEST");
println!("================================");

const GAME_INSTANCE_OFFSET: u64 = 0x8F8;
const LOCAL_PLAYERS_OFFSET: u64 = 0xF0;
const ACTORS_OFFSET: u64 = 0x2A0;

println!(
    "  UWorld global      : {:#018x}",
    uworld_global.to_umem()
);

println!(
    "  GameInstance off   : {:#x}",
    GAME_INSTANCE_OFFSET
);

println!(
    "  LocalPlayers off   : {:#x}",
    LOCAL_PLAYERS_OFFSET
);

println!(
    "  Actors off         : {:#x}",
    ACTORS_OFFSET
);

let game_instance_address =
    uworld_global.to_umem() + GAME_INSTANCE_OFFSET;

println!(
    "  GI calculated addr : {:#018x}",
    game_instance_address
);

println!("  Address arithmetic : PASS");
println!();
println!("  GameInstance read  :");
//
// TEST ive read of the Decrypt RVA
//
const DECRYPT_RVA: u64 = 0x108ED528;

println!();
println!("  UWorld live read");

match process.read::<u64>(uworld_global.into()) {
    Ok(value) => {
        println!(
            "    Raw value        : {:#018x}",
            value
        );

        println!(
            "    Canonical        : {}",
            value != 0
                && (value >> 48) == 0
        );

        println!("    Read             : PASS");
    }

    Err(error) => {
        println!(
            "    Read             : FAIL ({})",
            error
        );
    }
}


let decrypt_address =
    module.base.to_umem() + DECRYPT_RVA;

println!();
println!("  Decrypt RVA       : {:#x}", DECRYPT_RVA);
println!(
    "  Decrypt address   : {:#018x}",
    decrypt_address
);

match process.read::<u64>(decrypt_address.into()) {
    Ok(value) => {
        println!(
            "  Decrypt raw value : {:#018x}",
            value
        );
        println!("  Decrypt read      : PASS");

println!("  Decrypt target bytes:");

let decrypt_ptr = value;

//for i in 0..32u64 {
//for i in 0..128u64 {
for i in 0..256u64 {
    let address = decrypt_ptr + i;

    match process.read::<u8>(address.into()) {
        Ok(byte) => {
            print!("{:02x} ", byte);

            if i % 16 == 15 {
                println!();
            }
        }

        Err(_) => {
            print!("?? ");

            if i % 16 == 15 {
                println!();
            }
        }
    }
}

// ADD THE NEXT TEST HERE
let tmp1_add =
    match process.read::<i32>((decrypt_ptr + 3).into()) {
        Ok(value) => value as i64,
        Err(error) => {
            println!(
                "  Displacement read : FAIL ({})",
                error
            );
            0
        }
    };

let decrypt_key =
    (decrypt_ptr as i64 + tmp1_add + 7) as u64;

println!(
    "  RIP displacement  : {:#x}",
    tmp1_add
);

println!(
    "  Calculated key    : {:#018x}",
    decrypt_key
);


match process.read::<u64>(decrypt_key.into()) {
    Ok(value) => {
        println!(
            "  Key target value  : {:#018x}",
            value
        );
    }

    Err(error) => {
        println!(
            "  Key target read   : FAIL ({})",
            error
        );
    }
}



println!("  Key target bytes:");

for i in 0..64u64 {
    let address = decrypt_key + i;

    match process.read::<u8>(address.into()) {
        Ok(byte) => {
            print!("{:02x} ", byte);

            if i % 16 == 15 {
                println!();
            }
        }
        Err(_) => {
            print!("?? ");

            if i % 16 == 15 {
                println!();
            }
        }
    }
}



    }

    Err(error) => {
        println!(
            "  Decrypt read      : FAIL ({})",
            error
        );
    }
}


match process.read::<u64>(game_instance_address.into()) {
    Ok(value) => {
        println!(
            "    Raw value        : {:#018x}",
            value
        );

        if value == 0 {
            println!("    Result           : NULL");
        } else {
            println!("    Result           : READABLE");
        }
    }

    Err(error) => {
        println!(
            "    Result           : READ FAILED ({})",
            error
        );
    }
}

// --------------------------------------------------
// Discovery
// --------------------------------------------------
// --------------------------------------------------
// Discovery
// --------------------------------------------------

println!();
println!("================================");
println!("DISCOVERY");
println!("================================");

let candidates =
    discovery::discover_candidates(
        &mut process,
        module.base,
        &pe_info,
    )?;

println!();
println!(
    "Discovery returned {} candidates.",
    candidates.len()
);



// --------------------------------------------------
// Valthrun-inspired pattern discovery test
// --------------------------------------------------

let pattern_test_start =
    module.base.to_umem();

let pattern_test_size =
    0x1000usize;

let pattern_test =
    "48 8B ?? ?? ?? ?? ??";

let _pattern_test_result =
    discovery::test_pattern_discovery(
        &mut process,
        pattern_test_start,
        pattern_test_size,
        pattern_test,
    )?;



// --------------------------------------------------
// UWorld global
// --------------------------------------------------

println!();
println!("================================");
println!("DOWNSTREAM CHAIN TEST");
println!("================================");

println!();
println!("IMPORTANT:");
println!("This test ASSUMES the UWorld pointer is valid.");
println!("It does NOT decrypt or validate the UWorld global.");

let uworld_global =
    module.base + UWORLD;

println!();
println!(
    "UWorld global address : {:#x}",
    uworld_global
);

let uworld =
    match process.read::<u64>(uworld_global) {
        Ok(value) => value,

        Err(error) => {
            println!(
                "Could not read UWorld global: {}",
                error
            );

            return Ok(());
        }
    };

println!();
println!("UWorld global runtime inputs");
println!("============================");

println!(
    "UWorld global      : {:#018x}",
    uworld_global
);

println!(
    "Raw UWorld value   : {:#018x}",
    uworld
);

for offset in [0x00u64, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30] {
    let address = uworld_global + offset;

    match process.read::<u64>(address.into()) {
        Ok(value) => {
            println!(
                "  +{:#04x} [{:#018x}] -> {:#018x}",
                offset,
                address,
                value
            );
        }
        Err(error) => {
            println!(
                "  +{:#04x} [{:#018x}] -> READ FAILED: {}",
                offset,
                address,
                error
            );
        }
    }
}


println!();
println!("Candidate root validation");
println!("-------------------------");

println!(
    "Global address : {:#018x}",
    uworld_global
);

println!(
    "Raw value      : {:#018x}",
    uworld
);

// Basic canonical-address check for x64 Windows.
let canonical =
    uworld != 0
        && (
            (uworld >> 48) == 0
                || (uworld >> 48) == 0xffff
        );

println!(
    "Canonical x64  : {}",
    if canonical { "YES" } else { "NO" }
);

// Check whether the value falls inside the target module.
let module_start =
    module.base.to_umem();

let module_end =
    module_start + module.size;

let inside_module =
    uworld >= module_start
        && uworld < module_end;

println!(
    "Inside module  : {}",
    if inside_module { "YES" } else { "NO" }
);

// Small read from the candidate address.
if canonical && uworld != 0 {
    match process.read::<u64>(uworld.into()) {
        Ok(first_qword) => {
            println!(
                "Read @ candidate: OK -> {:#018x}",
                first_qword
            );
        }

        Err(error) => {
            println!(
                "Read @ candidate: FAILED -> {}",
                error
            );
        }
    }
} else {
    println!(
        "Read @ candidate: SKIPPED (value is not a plausible canonical address)"
    );
}

// UWorld global qword map

println!();
println!("UWorld global qword map");
println!("======================");

let module_start = module.base.to_umem();
let module_end = module_start + module.size;

for offset in (0u64..0x100).step_by(8) {
    let address = uworld_global + offset;

    match process.read::<u64>(address.into()) {
        Ok(value) => {
            let canonical =
                value != 0
                    && (value >> 48) == 0
                    && value >= 0x1_0000
                    && value < 0x0000_8000_0000_0000;

            let inside_module =
                canonical
                    && value >= module_start
                    && value < module_end;

            println!(
                "+{:#04x}  {:#018x}  canonical={}  module={}",
                offset,
                value,
                if canonical { "YES" } else { "NO" },
                if inside_module { "YES" } else { "NO" }
            );
        }

        Err(error) => {
            println!(
                "+{:#04x}  READ FAILED: {}",
                offset,
                error
            );
        }
    }
}




println!("Page-read test");

for address in [
    0x7ff753864000u64,
    0x7ff753865000u64,
    0x7ff753866000u64,
    0x7ff753867000u64,
] {
    match process.read::<u64>(address.into()) {
        Ok(value) => println!("{:#018x} -> {:#018x} READABLE", address, value),
        Err(error) => println!("{:#018x} -> READ FAILED: {}", address, error),
    }
}





// --------------------------------------------------
// Interesting pointer targets
// --------------------------------------------------

println!();
println!("Interesting pointer targets");
println!("==========================");

for (name, offset) in [
    ("+0x58", 0x58u64),
    ("+0x60", 0x60u64),
] {
    let field_address = uworld_global + offset;

    let target = match process.read::<u64>(field_address.into()) {
        Ok(value) => value,
        Err(error) => {
            println!("{} READ FAILED: {}", name, error);
            continue;
        }
    };

    println!();
    println!(
        "{} field [{:#018x}] -> {:#018x}",
        name,
        field_address,
        target
    );

    if target >= module_start && target < module_end {
        println!("  Target is inside module: YES");
        println!(
            "  Module range: [{:#018x}, {:#018x})",
            module_start,
            module_end
        );
    } else {
        println!("  Target is inside module: NO");
        continue;
    }

    // +0x58: inspect the target as a pointer table
    if name == "+0x58" {
        println!();
        println!("+0x58 pointer table");
        println!("===================");

        for i in 0..16u64 {
            let address = target + (i * 8);

            match process.read::<u64>(address.into()) {
                Ok(value) => {
                    println!(
                        "  +{:#04x} [{:#018x}] -> {:#018x}",
                        i * 8,
                        address,
                        value
                    );
                }
                Err(error) => {
                    println!(
                        "  +{:#04x} [{:#018x}] -> READ FAILED: {}",
                        i * 8,
                        address,
                        error
                    );
                }
            }
        }
    }

    // +0x60: inspect the target as executable code
    if name == "+0x60" {
        println!();
        println!("+0x60 target dump");
        println!("=================");

        println!("Target : {:#018x}", target);

        let target_rva = target - module_start;

        println!("Target RVA : {:#010x}", target_rva);


println!();
println!("UWorld +0x60 context");
println!("====================");

for offset in [0x00u64, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30] {
    let address = uworld_global + offset;

    match process.read::<u64>(address.into()) {
        Ok(value) => {
            println!(
                "  +{:#04x} [{:#018x}] -> {:#018x}",
                offset,
                address,
                value
            );
        }
        Err(error) => {
            println!(
                "  +{:#04x} [{:#018x}] -> READ FAILED: {}",
                offset,
                address,
                error
            );
        }
    }
}


        println!();
        println!("Instruction bytes");
        println!("-----------------");

        // for i in 0..96u64 {
        // for i in 0..256u64 {
        for i in 0..512u64 {
            match process.read::<u8>((target + i).into()) {
                Ok(byte) => print!("{:02x} ", byte),
                Err(_) => print!("?? "),
            }

            if (i + 1) % 16 == 0 {
                println!();
            }
        }
    }
}

// --------------------------------------------------
// Optional downstream chain

if uworld == 0 {
    println!();
    println!("UWorld value is NULL.");
    return Ok(());
}

if !canonical {
    println!();
    println!(
        "UWorld value is not a plausible canonical x64 address."
    );
    println!(
        "Downstream chain test skipped."
    );
    return Ok(());
}

// --------------------------------------------------
// GameInstance
// --------------------------------------------------

println!();
println!("1. GameInstance");
println!("----------------");

let game_instance_addr =
    uworld + GAME_INSTANCE;

let game_instance =
    match read_ptr(
        &mut process,
        game_instance_addr.into(),
        "GameInstance",
    ) {
        Some(value) => value,
        None => return Ok(()),
    };

// --------------------------------------------------
// LocalPlayer
// --------------------------------------------------

println!();
println!("2. LocalPlayer");
println!("---------------");

let local_player_addr =
    game_instance + LOCAL_PLAYER;

let local_player =
    match read_ptr(
        &mut process,
        local_player_addr.into(),
        "LocalPlayer",
    ) {
        Some(value) => value,
        None => return Ok(()),
    };

// --------------------------------------------------
// PlayerController
// --------------------------------------------------

println!();
println!("3. PlayerController");
println!("-------------------");

let controller_addr =
    local_player + PLAYER_CONTROLLER;

let controller =
    match read_ptr(
        &mut process,
        controller_addr.into(),
        "PlayerController",
    ) {
        Some(value) => value,
        None => return Ok(()),
    };

// --------------------------------------------------
// AcknowledgedPawn
// --------------------------------------------------

println!();
println!("4. AcknowledgedPawn");
println!("-------------------");

let pawn_addr =
    controller + ACKNOWLEDGED_PAWN;

let pawn =
    match read_ptr(
        &mut process,
        pawn_addr.into(),
        "AcknowledgedPawn",
    ) {
        Some(value) => value,
        None => return Ok(()),
    };

// --------------------------------------------------
// Character name field
// --------------------------------------------------

println!();
println!("5. Character field");
println!("------------------");

let character_name_addr =
    pawn + CHARACTER_NAME;

let character_name_value =
    match process.read::<u64>(
        character_name_addr.into()
    ) {
        Ok(value) => {
            println!(
                "CharacterName field [{:#x}] -> {:#x}",
                character_name_addr,
                value
            );

            value
        }

        Err(error) => {
            println!(
                "CharacterName READ FAILED: {}",
                error
            );

            0
        }
    };

// --------------------------------------------------
// RootComponent
// --------------------------------------------------

println!();
println!("6. RootComponent");
println!("----------------");

let root_component_addr =
    pawn + ROOT_COMPONENT;

let root_component =
    match read_ptr(
        &mut process,
        root_component_addr.into(),
        "RootComponent",
    ) {
        Some(value) => value,
        None => return Ok(()),
    };

// --------------------------------------------------
// Position
// --------------------------------------------------

println!();
println!("7. RootComponent position");
println!("-------------------------");

let position_addr =
    root_component + ROOT_COMPONENT_POS;

println!(
    "Position address: {:#x}",
    position_addr
);

let x =
    match process.read::<f32>(
        position_addr.into()
    ) {
        Ok(value) => value,

        Err(error) => {
            println!("X read failed: {}", error);
            return Ok(());
        }
    };

let y =
    match process.read::<f32>(
        (position_addr + 4).into()
    ) {
        Ok(value) => value,

        Err(error) => {
            println!("Y read failed: {}", error);
            return Ok(());
        }
    };

let z =
    match process.read::<f32>(
        (position_addr + 8).into()
    ) {
        Ok(value) => value,

        Err(error) => {
            println!("Z read failed: {}", error);
            return Ok(());
        }
    };

println!();
println!("Position:");
println!("  X = {}", x);
println!("  Y = {}", y);
println!("  Z = {}", z);


// --------------------------------------------------
// Final result
// --------------------------------------------------

println!();
println!("================================");
println!("RESULT");
println!("================================");

println!("UWorld          : {:#x}", uworld);
println!(
    "GameInstance    : {:#x}",
    game_instance
);
println!(
    "LocalPlayer     : {:#x}",
    local_player
);
println!(
    "PlayerController: {:#x}",
    controller
);
println!(
    "AcknowledgedPawn: {:#x}",
    pawn
);
println!(
    "RootComponent   : {:#x}",
    root_component
);
println!(
    "CharacterNameRaw: {:#x}",
    character_name_value
);

println!();
println!("Position:");
println!("  X = {}", x);
println!("  Y = {}", y);
println!("  Z = {}", z);

println!();
println!(
    "This result assumes the raw UWorld value is already"
);
println!(
    "the actual UWorld address."
);

Ok(())
 

}



