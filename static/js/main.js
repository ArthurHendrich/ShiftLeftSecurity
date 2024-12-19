// Vulnerable JavaScript with exposed API calls
document.addEventListener('DOMContentLoaded', function() {
    // Fetch and display all users without authentication
    fetch('/api/users')
        .then(response => response.json())
        .then(data => {
            const userList = document.getElementById('userList');
            if (userList) {
                data.forEach(user => {
                    userList.innerHTML += `
                        <div class="card mb-2">
                            <div class="card-body">
                                <p>Username: ${user[1]}</p>
                                <p>Email: ${user[3]}</p>
                                <p>Password Hash: ${user[2]}</p>
                            </div>
                        </div>
                    `;
                });
            }
        });

    // Expose debug information in console
    fetch('/debug')
        .then(response => response.json())
        .then(data => {
            console.log('Debug Information:', data);
        });
});
