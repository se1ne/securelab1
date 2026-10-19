const registerResult =
    document.querySelector("#registerResult");

const loginResult =
    document.querySelector("#loginResult");

const profileResult =
    document.querySelector("#profileResult");

const incidentResult =
    document.querySelector("#incidentResult");

const logoutResult =
    document.querySelector("#logoutResult");


async function apiFetch(path, options = {}) {
    return fetch(path, {
        ...options,
        credentials: "same-origin"
    });
}


async function refreshProfile() {
    const response =
        await apiFetch("/api/me");

    if (response.status === 401) {
        profileResult.textContent =
            "401: користувач не автентифікований.";
        return;
    }

    if (!response.ok) {
        profileResult.textContent =
            `Помилка отримання профілю: ${response.status}`;
        return;
    }

    const profile =
        await response.json();

    profileResult.textContent =
        `ID: ${profile.id}\n` +
        `UserName: ${profile.userName}\n` +
        `DisplayName: ${profile.displayName}`;
}


document
    .querySelector("#register")
    .addEventListener("submit", async event => {
        event.preventDefault();

        const form = event.currentTarget;
        const formData = new FormData(form);

        const body = {
            userName: formData.get("userName"),
            email: formData.get("email"),
            displayName: formData.get("displayName"),
            password: formData.get("password")
        };

        const response =
            await apiFetch(
                "/api/auth/register",
                {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify(body)
                });

        form.elements.password.value = "";

        if (response.status === 201) {
            const created =
                await response.json();

            registerResult.textContent =
                `Register: 201\n` +
                `ID: ${created.id}\n` +
                `UserName: ${created.userName}\n` +
                `DisplayName: ${created.displayName}`;

            return;
        }

        registerResult.textContent =
            `Register: ${response.status}`;
    });


document
    .querySelector("#login")
    .addEventListener("submit", async event => {
        event.preventDefault();

        const form = event.currentTarget;
        const formData = new FormData(form);

        const body = {
            userName: formData.get("userName"),
            password: formData.get("password")
        };

        const response =
            await apiFetch(
                "/api/auth/login",
                {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify(body)
                });

        form.elements.password.value = "";

        loginResult.textContent =
            `Login: ${response.status}`;

        if (response.status === 204) {
            await refreshProfile();
        }
    });


document
    .querySelector("#me")
    .addEventListener("click", async () => {
        await refreshProfile();
    });


document
    .querySelector("#incident")
    .addEventListener("submit", async event => {
        event.preventDefault();

        const form = event.currentTarget;
        const formData = new FormData(form);

        const localDate =
            new Date(formData.get("occurredAtUtc"));

        const body = {
            title: formData.get("title"),
            description: formData.get("description"),
            severity: formData.get("severity"),
            occurredAtUtc: localDate.toISOString()
        };

        const response =
            await apiFetch(
                "/api/incidents",
                {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify(body)
                });

        if (response.status === 201) {
            const created =
                await response.json();

            incidentResult.textContent =
                `Create: 201\n` +
                `ID: ${created.id}\n` +
                `Title: ${created.title}\n` +
                `Severity: ${created.severity}\n` +
                `Status: ${created.status}`;

            return;
        }

        incidentResult.textContent =
            `Create: ${response.status}`;
    });


document
    .querySelector("#logout")
    .addEventListener("click", async () => {
        const response =
            await apiFetch(
                "/api/auth/logout",
                {
                    method: "POST"
                });

        logoutResult.textContent =
            `Logout: ${response.status}`;

        profileResult.textContent = "";
        incidentResult.textContent = "";

        await refreshProfile();
    });


refreshProfile();