#[derive(Debug, thiserror::Error)]
pub enum DetectionError {
    #[error("honeypot triggered")]
    HoneypotTriggered,
    #[error("anomaly detected")]
    AnomalyDetected,
}

#[derive(Debug, Clone)]
pub struct TelemetrySnapshot {
    pub active_users: u32,
    pub module_switches: u32,
    pub request_rate: u32,
}

pub struct DetectionLayer {
    anomaly_threshold: u32,
    events: Vec<String>,
}

impl DetectionLayer {
    pub fn new(anomaly_threshold: u32) -> Self {
        Self {
            anomaly_threshold,
            events: Vec::new(),
        }
    }

    pub fn check_honeypot(&self, called: bool) -> Result<(), DetectionError> {
        if called {
            return Err(DetectionError::HoneypotTriggered);
        }
        Ok(())
    }

    pub fn check_anomaly(&self, snap: &TelemetrySnapshot) -> Result<(), DetectionError> {
        if snap.active_users > self.anomaly_threshold {
            return Err(DetectionError::AnomalyDetected);
        }
        Ok(())
    }

    pub fn record_event(&mut self, event: &str) {
        self.events.push(event.to_string());
    }

    pub fn events(&self) -> &[String] {
        &self.events
    }

    pub fn should_silent_kill(&self, snap: &TelemetrySnapshot) -> bool {
        snap.active_users > self.anomaly_threshold * 2
    }
}
