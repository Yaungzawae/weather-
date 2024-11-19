// 显示模态框
function showModal() {
  document.getElementById('authModal').style.display = 'block';
}

var logo = document.getElementById('logo');
logo.addEventListener('click', function(){
  window.location.href = '/';
});


// 切换选项卡
function showTab(tabName) {
  // 隐藏所有选项卡内容
  const tabContents = document.querySelectorAll('.tab-content');
  tabContents.forEach((tabContent) => {
    tabContent.classList.remove('active');
  });

  // 显示选中的选项卡内容
  document.getElementById(`${tabName}Tab`).classList.add('active');
}

// 处理登录表单提交
async function handleLoginFormSubmit(e) {
  e.preventDefault();
  const formData = new FormData(e.target);
  const username = formData.get('username');
  const password = formData.get('password');

  try {
    const response = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    const result = await response.json();
    if (response.ok) {
      // 显示用户信息
      document.getElementById('userInfo').style.display = 'block';
      document.getElementById('usernameDisplay').textContent = result.user.username;
      document.getElementById('userAvatar').src = result.user.avatar || 'default-avatar.png';
      // 关闭模态框
      document.getElementById('authModal').style.display = 'false';
    } else {
      alert('Login failed: ' + result.message);
    }
  } catch (error) {
    console.error('Login error:', error);
  }
}

// 处理注册表单提交
async function handleRegisterFormSubmit(e) {
  e.preventDefault();
  const formData = new FormData(e.target);

  try {
    const response = await fetch('/api/register', {
      method: 'POST',
      body: formData,
    });
    const result = await response.json();
    if (response.ok) {
      alert('Registration successful!');
      showTab('login');
    } else {
      alert('Registration failed: ' + result.message);
    }
  } catch (error) {
    console.error('Registration error:', error);
  }
}

// 处理找回密码表单提交
async function handleRecoverFormSubmit(e) {
  e.preventDefault();
  const formData = new FormData(e.target);
  const email = formData.get('email');

  try {
    const response = await fetch('/api/recover', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
    });
    const result = await response.json();
    if (response.ok) {
      // 存储重置令牌
      const resetToken = result.resetToken;
      // 显示重置密码选项卡
      showTab('resetPassword');
      // 设置令牌到隐藏输入框
      document.getElementById('resetToken').value = resetToken;
    } else {
      alert('Recovery failed: ' + result.message);
    }
  } catch (error) {
    console.error('Recovery error:', error);
  }
}

// 处理重置密码表单提交
async function handleResetPasswordFormSubmit(e) {
  e.preventDefault();
  const formData = new FormData(e.target);
  const token = formData.get('token');
  const password = formData.get('password');

  try {
    const response = await fetch('/api/reset-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token, password }),
    });
    const result = await response.json();
    if (response.ok) {
      alert('Password has been reset successfully!');
      showTab('login');
    } else {
      alert('Reset failed: ' + result.message);
    }
  } catch (error) {
    console.error('Reset error:', error);
  }
}

// 绑定表单提交事件
document.getElementById('loginForm').addEventListener('submit', handleLoginFormSubmit);
document.getElementById('registerForm').addEventListener('submit', handleRegisterFormSubmit);
document.getElementById('recoverForm').addEventListener('submit', handleRecoverFormSubmit);
document.getElementById('resetPasswordForm').addEventListener('submit', handleResetPasswordFormSubmit);