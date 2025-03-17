document.getElementById("resetPasswordForm").addEventListener("submit", async function(event) {
  event.preventDefault();

  const token = document.getElementById("token").value.trim();
  const newPassword = document.getElementById("password").value.trim();
  const confirmPassword = document.getElementById("confirmPassword").value.trim();

  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>]).{8,}$/;

  // Validaciones
  if (!newPassword || newPassword.length < 8) {
      showModal("Error de Validación", "La contraseña debe tener al menos 8 caracteres.");
      return;
  }

  if (!passwordRegex.test(newPassword)) {
      showModal("Error de Validación", "La contraseña debe contener al menos una letra mayúscula, una minúscula, un número y un carácter especial.");
      return;
  }

  if (newPassword !== confirmPassword) {
      showModal("Error de Validación", "Las contraseñas no coinciden.");
      return;
  }

  // Mostrar el modal de carga
  const loadingModal = new bootstrap.Modal(document.getElementById("loadingModal"));
  loadingModal.show();

  try {
      const response = await fetch("/reset-password", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ token, new_password: newPassword })
      });

      loadingModal.hide(); // Ocultar modal de carga
      document.querySelector('.modal-backdrop')?.remove(); 

      const result = await response.json();

      if (response.ok) {
          showModal("Contraseña Restablecida", result.message, true);
      } else {
          showModal("Error", result.message);
      }
  } catch (error) {
      console.error("Error:", error);
      loadingModal.hide();
      document.querySelector('.modal-backdrop')?.remove();
      showModal("Error", "No se pudo conectar al servidor. Por favor, intenta más tarde.");
  }
});

function showModal(title, message, redirect = false) {
  document.querySelectorAll('.modal-backdrop').forEach(backdrop => backdrop.remove());

  document.getElementById("responseModalLabel").textContent = title;
  document.getElementById("modalMessage").textContent = message;

  const responseModal = new bootstrap.Modal(document.getElementById("responseModal"));
  responseModal.show();

  if (redirect) {
      responseModal._element.addEventListener("hidden.bs.modal", function () {
          window.location.href = "http://127.0.0.1:5501/SkillSwap/pages/auth/login.html";
      });
  }
}

document.addEventListener("DOMContentLoaded", function () {
    const passwordInput = document.getElementById("password"); // ID correcto
    const togglePasswordButton = document.getElementById("togglePassword");
    const icon = togglePasswordButton.querySelector("i");

    togglePasswordButton.addEventListener("click", function () {
        if (passwordInput.type === "password") {
            passwordInput.type = "text";
            icon.classList.remove("bi-eye");
            icon.classList.add("bi-eye-slash");
        } else {
            passwordInput.type = "password";
            icon.classList.remove("bi-eye-slash");
            icon.classList.add("bi-eye");
        }
    });
});
