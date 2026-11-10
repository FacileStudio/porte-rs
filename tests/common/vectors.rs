use serde_json::Value;

const SOURCE: &str = "github.com/FacileStudio/porte@v0.16.1";
const DIRECTORY_SOURCE: &str = "github.com/FacileStudio/porte/directory@v0.3.0";

pub fn load(subject: &str) -> Value {
    let path = format!("{}/tests/vectors/{subject}.json", env!("CARGO_MANIFEST_DIR"));
    let vector: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let source = if subject == "directory_snapshot" { DIRECTORY_SOURCE } else { SOURCE };
    assert_eq!(
        vector["source"], source,
        "{path} names another source than the v0.16.1 tree pinned in tests/vectors/SOURCE"
    );
    assert_eq!(vector["subject"], subject);
    vector
}

pub fn cases(vector: &Value) -> &Vec<Value> {
    vector["cases"].as_array().expect("a vector carries cases")
}

pub fn source_file() -> String {
    std::fs::read_to_string(format!("{}/tests/vectors/SOURCE", env!("CARGO_MANIFEST_DIR"))).unwrap()
}
