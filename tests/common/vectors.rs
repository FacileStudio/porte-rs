use serde_json::Value;

const SOURCE: &str = "github.com/FacileStudio/porte@v0.16.1";

pub fn load(subject: &str) -> Value {
    let path = format!("{}/tests/vectors/{subject}.json", env!("CARGO_MANIFEST_DIR"));
    let vector: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(vector["source"], SOURCE, "{path} names another source than tests/vectors/SOURCE");
    assert_eq!(vector["subject"], subject);
    vector
}

pub fn cases(vector: &Value) -> &Vec<Value> {
    vector["cases"].as_array().expect("a vector carries cases")
}

pub fn source_file() -> String {
    std::fs::read_to_string(format!("{}/tests/vectors/SOURCE", env!("CARGO_MANIFEST_DIR"))).unwrap()
}
