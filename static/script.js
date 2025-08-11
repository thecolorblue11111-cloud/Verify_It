/* Client-side JS for Proof Logger
 * - Handles audio recording (MediaRecorder)
 * - Prepares form data (including audio blob) for upload
 * - Small UI helpers: preview file names, toggle record button
 */

const FORM_UPLOAD_URL = "/create_log"; // Flask upload endpoint

// Elements (expect these IDs in your new_log template)
const recordBtn = document.getElementById("record-btn");
const stopBtn = document.getElementById("stop-btn");
const audioPreview = document.getElementById("audio-preview");
const audioPlayer = document.getElementById("audio-player");
const fileInput = document.getElementById("file-input");
const attachList = document.getElementById("attach-list");
const logForm = document.getElementById("log-form");

let mediaRecorder = null;
let audioChunks = [];

// --- Audio recording setup ---
async function startRecording() {
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    alert("Audio recording not supported in this browser.");
    return;
  }
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    mediaRecorder = new MediaRecorder(stream);
    audioChunks = [];
    mediaRecorder.ondataavailable = e => audioChunks.push(e.data);
    mediaRecorder.onstop = buildAudioBlob;
    mediaRecorder.start();
    toggleRecordingUI(true);
  } catch (err) {
    console.error("Error accessing microphone:", err);
    alert("Could not access microphone. Please check permissions.");
  }
}

function stopRecording() {
  if (mediaRecorder && mediaRecorder.state !== "inactive") {
    mediaRecorder.stop();
    // Stop all tracks to free up the microphone
    if (mediaRecorder.stream) {
      mediaRecorder.stream.getTracks().forEach(track => track.stop());
    }
    toggleRecordingUI(false);
  }
}

function toggleRecordingUI(recording) {
  if (recording) {
    recordBtn.disabled = true;
    stopBtn.disabled = false;
    recordBtn.classList.add("recording");
    recordBtn.textContent = "🔴 Recording...";
  } else {
    recordBtn.disabled = false;
    stopBtn.disabled = true;
    recordBtn.classList.remove("recording");
    recordBtn.textContent = "🎤 Record";
  }
}

function buildAudioBlob() {
  const blob = new Blob(audioChunks, { type: "audio/webm" });
  const url = URL.createObjectURL(blob);
  audioPlayer.src = url;
  audioPlayer.style.display = "block";
  audioPlayer.controls = true;
  // store blob on form element for upload
  audioPlayer.dataset.blob = url;
  audioPlayer._blob = blob; // nonstandard but handy for upload
  
  // Update UI
  if (audioPreview) {
    audioPreview.innerHTML = `Audio recorded (${Math.round(blob.size/1024)} KB)`;
  }
  if (attachList) {
    const audioDiv = document.createElement('div');
    audioDiv.textContent = `🎤 Audio recorded (${Math.round(blob.size/1024)} KB)`;
    attachList.appendChild(audioDiv);
  }
}

// --- File input preview ---
if (fileInput) {
  fileInput.addEventListener("change", () => {
    if (attachList) {
      // Clear previous file list but keep audio info
      const audioInfo = attachList.querySelector('div:has-text("🎤")') || 
                       Array.from(attachList.children).find(div => div.textContent.includes('🎤'));
      attachList.innerHTML = "";
      if (audioInfo) {
        attachList.appendChild(audioInfo);
      }
      
      // Add new files
      for (const f of fileInput.files) {
        const li = document.createElement("div");
        li.textContent = `📄 ${f.name} (${Math.round(f.size/1024)} KB)`;
        attachList.appendChild(li);
      }
    }
  });
}

// --- Form submission (send form + audio blob via Multipart) ---
if (logForm) {
  logForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    
    const submitButton = logForm.querySelector('button[type="submit"]');
    const originalText = submitButton.textContent;
    submitButton.textContent = 'Creating...';
    submitButton.disabled = true;
    
    const formData = new FormData(logForm);

    // if recorded audio exists, attach it
    if (audioPlayer && audioPlayer._blob) {
      formData.append("audio_file", audioPlayer._blob, `recording-${Date.now()}.webm`);
    }

    // Send via fetch to the backend
    try {
      const resp = await fetch(FORM_UPLOAD_URL, {
        method: "POST",
        body: formData,
      });
      
      if (resp.ok) {
        // Check if response is a redirect
        if (resp.redirected) {
          window.location.href = resp.url;
        } else {
          // Assume success, redirect to dashboard
          window.location.href = '/dashboard';
        }
      } else {
        const txt = await resp.text();
        alert("Upload failed: " + txt);
      }
    } catch (err) {
      console.error("Upload error:", err);
      alert("Network error while uploading. Please try again.");
    } finally {
      submitButton.textContent = originalText;
      submitButton.disabled = false;
    }
  });
}

// --- Attach button bindings ---
if (recordBtn) recordBtn.addEventListener("click", startRecording);
if (stopBtn) stopBtn.addEventListener("click", stopRecording);

// Initialize feather icons if available
document.addEventListener('DOMContentLoaded', function() {
  if (typeof feather !== 'undefined') {
    feather.replace();
  }
});
