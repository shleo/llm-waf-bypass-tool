// 标签页切换功能
document.addEventListener('DOMContentLoaded', function() {
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');

    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const tabId = btn.getAttribute('data-tab');

            // 移除所有 active 类
            tabBtns.forEach(b => b.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));

            // 添加 active 类到当前选中的标签
            btn.classList.add('active');
            document.getElementById(tabId).classList.add('active');
        });
    });
});

// 通用请求函数
async function makeRequest(url, options = {}) {
    const startTime = Date.now();
    try {
        const response = await fetch(url, options);
        const elapsed = Date.now() - startTime;
        const data = await response.json();

        return {
            success: true,
            data,
            status: response.status,
            elapsed
        };
    } catch (error) {
        return {
            success: false,
            error: error.message
        };
    }
}

// 格式化结果显示
function displayResult(resultBox, data, elapsed) {
    if (data.success) {
        let html = `
            <div class="success">
                <h3>请求成功</h3>
                <p><strong>响应时间:</strong> ${elapsed}ms</p>
        `;

        if (data.data && Array.isArray(data.data) && data.data.length > 0) {
            html += '<table><thead><tr>';
            const headers = Object.keys(data.data[0]);
            headers.forEach(h => {
                html += `<th>${h}</th>`;
            });
            html += '</tr></thead><tbody>';

            data.data.forEach(row => {
                html += '<tr>';
                headers.forEach(h => {
                    html += `<td>${row[h] || '-'}</td>`;
                });
                html += '</tr>';
            });
            html += '</tbody></table>';
        } else if (data.data && typeof data.data === 'object') {
            html += '<table><tbody>';
            Object.entries(data.data).forEach(([key, value]) => {
                html += `<tr><td><strong>${key}</strong></td><td>${value}</td></tr>`;
            });
            html += '</tbody></table>';
        } else {
            html += `<p>返回空结果</p>`;
        }

        if (data.query) {
            html += `
                <details>
                    <summary>查看 SQL 查询</summary>
                    <pre>${escapeHtml(data.query)}</pre>
                </details>
            `;
        }

        html += '</div>';
        resultBox.innerHTML = html;
    } else {
        resultBox.innerHTML = `
            <div class="error">
                <h3>请求失败</h3>
                <p>${data.error || '未知错误'}</p>
                ${data.query ? `<details><summary>查看 SQL 查询</summary><pre>${escapeHtml(data.query)}</pre></details>` : ''}
            </div>
        `;
    }
}

// HTML 转义
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// 测试用户信息查询 (GET 注入)
async function testUserInfo() {
    const userId = document.getElementById('user-id').value;
    const resultBox = document.getElementById('user-result');

    resultBox.innerHTML = '<div class="loading">查询中...</div>';

    const result = await makeRequest(`/api/user?id=${encodeURIComponent(userId)}`);

    if (result.success) {
        displayResult(resultBox, result.data, result.elapsed);
    } else {
        resultBox.innerHTML = `<div class="error">请求失败: ${result.error}</div>`;
    }
}

// 测试登录 (POST 注入)
async function testLogin() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const resultBox = document.getElementById('login-result');

    resultBox.innerHTML = '<div class="loading">登录中...</div>';

    const formData = new FormData();
    formData.append('username', username);
    formData.append('password', password);

    const result = await makeRequest('/login', {
        method: 'POST',
        body: formData
    });

    if (result.success) {
        const timestamp = new Date().toLocaleTimeString();
        const data = result.data;

        if (data.success) {
            resultBox.innerHTML = `
                <div class="success">
                    <h3>登录成功!</h3>
                    <p><strong>时间:</strong> ${timestamp}</p>
                    <p><strong>用户:</strong> ${data.user.username} (${data.user.role})</p>
                    <p><strong>邮箱:</strong> ${data.user.email}</p>
                    <p><strong>管理员:</strong> ${data.user.is_admin ? '是' : '否'}</p>
                    <details>
                        <summary>查看查询</summary>
                        <pre>${escapeHtml(data.query)}</pre>
                    </details>
                </div>
            `;
        } else {
            resultBox.innerHTML = `
                <div class="error">
                    <h3>登录失败</h3>
                    <p>${data.message}</p>
                    <details>
                        <summary>查看查询</summary>
                        <pre>${escapeHtml(data.query)}</pre>
                    </details>
                </div>
            `;
        }
    } else {
        resultBox.innerHTML = `<div class="error">请求失败: ${result.error}</div>`;
    }
}

// 测试搜索 (搜索注入)
async function testSearch() {
    const query = document.getElementById('search-query').value;
    const resultBox = document.getElementById('search-result');

    resultBox.innerHTML = '<div class="loading">搜索中...</div>';

    const result = await makeRequest(`/api/search?q=${encodeURIComponent(query)}`);

    if (result.success) {
        displayResult(resultBox, result.data, result.elapsed);
    } else {
        resultBox.innerHTML = `<div class="error">请求失败: ${result.error}</div>`;
    }
}

// 测试文章查询 (时间盲注)
async function testPosts() {
    const postId = document.getElementById('post-id').value;
    const resultBox = document.getElementById('posts-result');

    resultBox.innerHTML = '<div class="loading">查询中...</div>';
    const startTime = Date.now();

    const result = await makeRequest(`/api/posts?id=${encodeURIComponent(postId)}`);

    if (result.success) {
        displayResult(resultBox, result.data, result.elapsed);
    } else {
        resultBox.innerHTML = `<div class="error">请求失败: ${result.error}</div>`;
    }
}

// 回车键触发查询
document.addEventListener('keypress', function(e) {
    if (e.key === 'Enter') {
        const activeElement = document.activeElement;
        if (activeElement.id === 'user-id') {
            testUserInfo();
        } else if (activeElement.id === 'search-query') {
            testSearch();
        } else if (activeElement.id === 'post-id') {
            testPosts();
        }
    }
});
