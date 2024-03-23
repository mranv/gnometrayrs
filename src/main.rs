use std::process::Command;
use std::collections::HashMap;

fn main() {
    let service_helper = ServiceHelper;
    let menu_item_data = service_helper.get_menu_item_data();

    // Print menu item data
    println!("{}", serde_json::to_string_pretty(&menu_item_data).unwrap());
}

struct ServiceHelper;

impl ServiceHelper {
    fn get_menu_item_data(&self) -> HashMap<String, HashMap<String, serde_json::Value>> {
        let osquery_paths = ["/usr/local/bin/osqueryi", "/usr/local/bin/osqueryctl"];
        let osquery_installed = osquery_paths.iter().all(|&path| std::path::Path::new(path).exists());

        // Log osquery installation status
        if osquery_installed {
            println!("osquery is installed");
        } else {
            eprintln!("osquery is not installed");
        }

        let wazuh_installed = self.is_wazuh_installed();

        // Log Wazuh installation status
        if wazuh_installed {
            println!("Wazuh is installed");
        } else {
            eprintln!("Wazuh is not installed");
        }

        let gatekeeper_enabled = self.is_gatekeeper_enabled();

        // Log Gatekeeper status
        if gatekeeper_enabled {
            println!("Gatekeeper is enabled");
        } else {
            println!("Gatekeeper is disabled");
        }

        let mut menu_item_data = HashMap::new();
        let mut menu_items = HashMap::new();

        // Construct menu item data
        menu_items.insert("text".to_string(), serde_json::Value::String("User Behavior Analytics".to_string()));
        menu_items.insert("icon".to_string(), serde_json::Value::String("staroflife.shield".to_string()));
        menu_items.insert("description".to_string(), serde_json::Value::String(format!("osquery is {}", if osquery_installed { "installed" } else { "not installed" })));
        menu_items.insert("status".to_string(), serde_json::Value::String(if osquery_installed { "informational".to_string() } else { "critical".to_string() }));

        menu_item_data.insert("menuItems".to_string(), menu_items);

        menu_item_data
    }

    fn is_wazuh_installed(&self) -> bool {
        let output = Command::new("/bin/bash")
            .args(&["-c", "ls /Library/Ossec/bin/"])
            .output()
            .expect("Failed to execute command");

        let output_str = String::from_utf8_lossy(&output.stdout);

        let required_files = vec!["agent-auth", "wazuh-control", "wazuh-modulesd", "manage_agents", "wazuh-execd", "wazuh-syscheckd", "wazuh-agentd", "wazuh-logcollector"];
        let is_installed = required_files.iter().all(|&file| output_str.contains(file));

        if !is_installed {
            eprintln!("Wazuh is not installed");
        }

        is_installed
    }

    fn is_gatekeeper_enabled(&self) -> bool {
        let output = Command::new("/bin/bash")
            .args(&["-c", "/bin/bash -c 'GateKeeper_Status=$(spctl --status) && echo \"<result>GK: $GateKeeper_Status</result>\"'"])
            .output()
            .expect("Failed to execute command");

        let output_str = String::from_utf8_lossy(&output.stdout);

        let is_enabled = output_str.contains("<result>GK: assessments enabled</result>");
        
        if !is_enabled {
            eprintln!("Gatekeeper is not enabled");
        }

        is_enabled
    }
}
