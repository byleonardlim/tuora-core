//! Local file ingestion and framework detection (Stage 2)

use crate::types::Framework;
use anyhow::{Context, Result};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, warn};

/// Supported file extensions for analysis
const SCAN_EXTENSIONS: &[&str] = &[
    "py", "ts", "js", "tsx", "yaml", "yml", "json", "svelte", "rs",
];

/// Framework detection patterns — matched as substrings against lowercased file content
const FRAMEWORK_PATTERNS: &[(&str, Framework)] = &[
    // Python agentic frameworks
    ("crewai", Framework::CrewAI),
    ("langgraph", Framework::LangGraph),
    ("langchain", Framework::LangChain),
    ("autogen", Framework::AutoGen),
    // TypeScript / JavaScript agentic frameworks (import strings)
    ("@openai/agents", Framework::OpenAIAgentsJS),
    ("@mastra/core", Framework::Mastra),
    ("@llamaindex/", Framework::LlamaIndexTS),
    ("llamaindex", Framework::LlamaIndexTS),
    ("@langchain/", Framework::LangChain),
    ("from \"ai\"", Framework::VercelAI),
    ("from 'ai'", Framework::VercelAI),
    // Standard AI SDKs (Python + JS/TS)
    ("openai", Framework::OpenAI),
    ("from \"openai\"", Framework::OpenAI),
    ("from 'openai'", Framework::OpenAI),
];

/// package.json dependency keys that signal a JS/TS agentic framework
const PACKAGE_JSON_PATTERNS: &[(&str, Framework)] = &[
    ("\"@openai/agents\"", Framework::OpenAIAgentsJS),
    ("\"@mastra/core\"", Framework::Mastra),
    ("\"llamaindex\"", Framework::LlamaIndexTS),
    ("\"@llamaindex/", Framework::LlamaIndexTS),
    ("\"@langchain/", Framework::LangChain),
    ("\"langgraph\"", Framework::LangGraph),
    ("\"ai\"", Framework::VercelAI),
    ("\"openai\"", Framework::OpenAI),
];

/// Ingested file with content
#[derive(Debug, Clone)]
pub struct IngestedFile {
    pub path: PathBuf,
    pub content: String,
    pub extension: String,
}

/// Workspace ingestion result
#[derive(Debug, Clone)]
pub struct WorkspaceSnapshot {
    #[allow(dead_code)]
    pub root: PathBuf,
    pub files: Vec<IngestedFile>,
    pub detected_framework: Framework,
    #[allow(dead_code)]
    pub manifest_files: Vec<PathBuf>,
}

/// File system scanner
pub struct Scanner {
    root: PathBuf,
    extensions: HashSet<String>,
    max_file_size: usize,
}

impl Scanner {
    /// Create new scanner with default settings
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            extensions: SCAN_EXTENSIONS.iter().map(|s| s.to_string()).collect(),
            max_file_size: 1024 * 1024, // 1MB max per file
        }
    }

    /// Scan workspace and ingest files
    pub fn scan(&self) -> Result<WorkspaceSnapshot> {
        let mut files = Vec::new();
        let mut manifest_files = Vec::new();

        self.collect_files(&self.root, &mut files, &mut manifest_files)?;

        let detected_framework = self.detect_framework(&files, &manifest_files);

        Ok(WorkspaceSnapshot {
            root: self.root.clone(),
            files,
            detected_framework,
            manifest_files,
        })
    }

    /// Recursively collect files
    fn collect_files(
        &self,
        dir: &Path,
        files: &mut Vec<IngestedFile>,
        manifests: &mut Vec<PathBuf>,
    ) -> Result<()> {
        if !dir.is_dir() {
            anyhow::bail!("Path is not a directory: {}", dir.display());
        }

        let entries = fs::read_dir(dir)
            .with_context(|| format!("Failed to read directory: {}", dir.display()))?;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                // Skip common non-source and output directories
                if let Some(name) = path.file_name() {
                    let name = name.to_string_lossy();
                    if name.starts_with('.')
                        || name == "node_modules"
                        || name == "__pycache__"
                        || name == "target"
                        || name == "build"
                        || name == "dist"
                        || name == "out"
                        || name == ".svelte-kit"
                        || name == ".next"
                        || name == ".nuxt"
                        || name == ".turbo"
                        || name == "storybook-static"
                        || name == ".docusaurus"
                        || name == "coverage"
                        || name == "venv"
                        || name == ".venv"
                    {
                        debug!("Skipping directory: {}", path.display());
                        continue;
                    }
                }
                self.collect_files(&path, files, manifests)?;
            } else if path.is_file() {
                self.process_file(&path, files, manifests)?;
            }
        }

        Ok(())
    }

    /// Process a single file
    fn process_file(
        &self,
        path: &Path,
        files: &mut Vec<IngestedFile>,
        manifests: &mut Vec<PathBuf>,
    ) -> Result<()> {
        let extension = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        // Check if this is a manifest file
        if let Some(filename) = path.file_name() {
            let filename = filename.to_string_lossy();
            if filename == "agents.yaml"
                || filename == "tasks.yaml"
                || filename == "pyproject.toml"
                || filename == "package.json"
                || filename == "requirements.txt"
            {
                manifests.push(path.to_path_buf());
            }
        }

        // Ingest .env* files (no extension, filename starts with ".env")
        let is_env_file = extension.is_empty()
            && path
                .file_name()
                .map(|n| n.to_string_lossy().starts_with(".env"))
                .unwrap_or(false);

        // Only ingest supported extensions (or .env* files)
        if !self.extensions.contains(&extension) && !is_env_file {
            return Ok(());
        }

        // Use synthetic extension tag for .env files so rules can branch on it
        let extension = if is_env_file {
            "env".to_string()
        } else {
            extension
        };

        // Check file size
        let metadata = fs::metadata(path)?;
        if metadata.len() > self.max_file_size as u64 {
            warn!(
                "Skipping large file: {} ({} bytes)",
                path.display(),
                metadata.len()
            );
            return Ok(());
        }

        // Read file content with defensive handling
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                // Binary or non-UTF8 file - skip silently
                debug!("Skipping non-text file: {}", path.display());
                return Ok(());
            }
            Err(e) => {
                return Err(e).with_context(|| format!("Failed to read file: {}", path.display()));
            }
        };

        files.push(IngestedFile {
            path: path.to_path_buf(),
            content,
            extension,
        });

        Ok(())
    }

    /// Detect framework from file content
    fn detect_framework(&self, files: &[IngestedFile], manifests: &[PathBuf]) -> Framework {
        // Check manifest files first (CrewAI-specific YAML topology files)
        for manifest in manifests {
            let filename = manifest.file_name().unwrap_or_default().to_string_lossy();
            if filename == "agents.yaml" || filename == "tasks.yaml" {
                return Framework::CrewAI;
            }
        }

        // Check package.json dependency keys for JS/TS frameworks
        for file in files {
            if file
                .path
                .file_name()
                .map(|n| n.to_string_lossy() == "package.json")
                .unwrap_or(false)
            {
                for (key, framework) in PACKAGE_JSON_PATTERNS {
                    if file.content.contains(key) {
                        debug!(file = %file.path.display(), "Detected framework via package.json: {}", framework.name());
                        return *framework;
                    }
                }
            }
        }

        // Check import strings in source files
        for file in files {
            for (pattern, framework) in FRAMEWORK_PATTERNS {
                if file.content.contains(pattern) {
                    debug!(file = %file.path.display(), "Detected framework via import: {}", framework.name());
                    return *framework;
                }
            }
        }

        Framework::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_scanner_finds_python_files() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("test.py");
        let mut file = fs::File::create(&file_path).unwrap();
        writeln!(file, "import crewai").unwrap();

        let scanner = Scanner::new(temp.path());
        let snapshot = scanner.scan().unwrap();

        assert_eq!(snapshot.files.len(), 1);
        assert_eq!(snapshot.detected_framework, Framework::CrewAI);
    }

    #[test]
    fn test_scanner_detects_openai_sdk_python() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("openai_app.py");
        let mut file = fs::File::create(&file_path).unwrap();
        writeln!(file, "from openai import OpenAI").unwrap();
        writeln!(file, "client = OpenAI()").unwrap();

        let scanner = Scanner::new(temp.path());
        let snapshot = scanner.scan().unwrap();

        assert_eq!(snapshot.files.len(), 1);
        assert_eq!(snapshot.detected_framework, Framework::OpenAI);
    }

    #[test]
    fn test_scanner_detects_openai_sdk_js() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("openai_app.ts");
        let mut file = fs::File::create(&file_path).unwrap();
        writeln!(file, "import OpenAI from 'openai';").unwrap();
        writeln!(file, "const client = new OpenAI();").unwrap();

        let scanner = Scanner::new(temp.path());
        let snapshot = scanner.scan().unwrap();

        assert_eq!(snapshot.files.len(), 1);
        assert_eq!(snapshot.detected_framework, Framework::OpenAI);
    }

    #[test]
    fn test_scanner_detects_openai_package_json() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("package.json");
        let mut file = fs::File::create(&file_path).unwrap();
        writeln!(file, "{{").unwrap();
        writeln!(file, "  \"dependencies\": {{").unwrap();
        writeln!(file, "    \"openai\": \"^4.0.0\"").unwrap();
        writeln!(file, "  }}").unwrap();
        writeln!(file, "}}").unwrap();

        let scanner = Scanner::new(temp.path());
        let snapshot = scanner.scan().unwrap();

        assert_eq!(snapshot.detected_framework, Framework::OpenAI);
    }
}
