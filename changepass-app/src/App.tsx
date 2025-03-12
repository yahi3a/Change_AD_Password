import React, { useState } from 'react';
import axios, { AxiosResponse } from 'axios';
import './App.css';
interface Translation {
  title: string;
  loginUsernameLabel: string;
  loginPasswordLabel: string;
  loginButton: string;
  loginError: string;
  welcome: string;
  usernameLabel: string;
  newPasswordLabel: string;
  confirmLabel: string;
  changePasswordButton: string;
  successMessage: string;
  matchError: string;
  fieldsError: string;
  logoutButton: string;
  loginPlaceholder: string;
  passwordPlaceholder: string;
  newPasswordPlaceholder: string;
  confirmPlaceholder: string;
  passwordRequirement: string;
}

interface Translations {
  en: Translation;
  vi: Translation;
}

function App() {
  // State for login
  const [loginUsername, setLoginUsername] = useState<string>('');
  const [loginPassword, setLoginPassword] = useState<string>('');
  const [loggedIn, setLoggedIn] = useState<boolean>(false);
  const [loginMessage, setLoginMessage] = useState<React.ReactNode>('');
  const [showLoginPassword, setShowLoginPassword] = useState<boolean>(false);  // State for password change
  const [username, setUsername] = useState<string>('');
  const [password, setPassword] = useState<string>('');
  const [confirmPassword, setConfirmPassword] = useState<string>('');
  const [message, setMessage] = useState<React.ReactNode>('');
  const [showNewPassword, setShowNewPassword] = useState<boolean>(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState<boolean>(false);  // State for language
  const [language, setLanguage] = useState<'en' | 'vi'>('en');  // Translation object with TypeScript interface
  const translations: Translations = {
    en: {
      title: 'GELEXIMCO - ACCOUNT MANAGEMENT',
      loginUsernameLabel: 'Username: ',
      loginPasswordLabel: 'Password: ',
      loginButton: 'Login',
      loginError: 'Invalid username or password.',
      welcome: 'Welcome, ',
      usernameLabel: 'Username: ',
      newPasswordLabel: 'New Password: ',
      confirmLabel: 'Confirm: ',
      changePasswordButton: 'Change Password',
      successMessage: 'Password changed successfully for ',
      matchError: 'Passwords do not match.',
      fieldsError: 'Please fill in all fields.',
      logoutButton: 'Logout',
      loginPlaceholder: 'user@dragondoson.vn',
      passwordPlaceholder: 'Enter current password',
      newPasswordPlaceholder: 'Enter new password',
      confirmPlaceholder: 'Re-enter new password',
      passwordRequirement: 'The password must be at least 11 characters long and contain at least three of these four elements: an uppercase letter, a lowercase letter, a number, and a special character. It must also NOT include your USERNAME.',
    },
    vi: {
      title: 'GELEXIMCO - QUẢN LÝ TÀI KHOẢN',
      loginUsernameLabel: 'Tên đăng nhập: ',
      loginPasswordLabel: 'Mật khẩu: ',
      loginButton: 'Đăng nhập',
      loginError: 'Tên đăng nhập hoặc mật khẩu không đúng.',
      welcome: 'Xin chào nhé, ',
      usernameLabel: 'Tên đăng nhập: ',
      newPasswordLabel: 'Mật khẩu mới: ',
      confirmLabel: 'Xác nhận: ',
      changePasswordButton: 'Đổi mật khẩu',
      successMessage: 'Mật khẩu đã được thay đổi thành công cho ',
      matchError: 'Mật khẩu không khớp.',
      fieldsError: 'Vui lòng điền đầy đủ các mục.',
      logoutButton: 'Đăng xuất',
      loginPlaceholder: 'user@dragondoson.vn',
      passwordPlaceholder: 'Nhập mật khẩu hiện tại',
      newPasswordPlaceholder: 'Nhập mật khẩu mới',
      confirmPlaceholder: 'Nhập lại mật khẩu mới',
      passwordRequirement: 'Mật khẩu dài tối thiểu 11 ký tự và chứa ít nhất ba trong bốn yếu tố sau: chữ viết hoa, chữ viết thường, số và ký tự đặc biệt. Ngoài ra, KHÔNG ĐƯỢC bao gồm TÊN NGƯỜI DÙNG của bạn.',
    },
  };  
  
  // API base URL (adjust for local or deployed backend)
  const API_URL = 'http://localhost:3001/api'; // Match your backend port  
   
  // Handle login submission
const handleLogin = async (event: React.FormEvent<HTMLFormElement>) => {
  event.preventDefault();
  try {
    const response = await axios.post(`${API_URL}/login`, {
      username: loginUsername,
      password: loginPassword,
    });
    if (response.data.success) {
      setLoggedIn(true);
      setUsername(response.data.username);
      setLoginMessage('');
      setLoginUsername('');
      setLoginPassword('');
    } else {
      setLoginMessage(<p className="error">{translations[language].loginError}</p>);
      setTimeout(() => setLoginMessage(''), 2000); // Clear after 2 seconds
    }
  } catch (error) {
    console.error('Login Error:', error);
    setLoginMessage(<p className="error">{translations[language].loginError}</p>);
    setTimeout(() => setLoginMessage(''), 2000);
  }
};  
  // Handle password change submission
const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
  event.preventDefault();
  const passwordRegex = /^(?!.*username$)(?=(?:[^A-Z]*[A-Z]){1,})(?=(?:[^a-z]*[a-z]){1,})(?=(?:[^0-9]*[0-9]){1,})(?=(?:[^@#$!%*?&]*[@#$!%*?&]){1,}).{11,}$/;
  if (username && password && confirmPassword) {
    if (!passwordRegex.test(password)) {
      setMessage(<p className="error">{translations[language].passwordRequirement}</p>);
      setTimeout(() => {
        setMessage('');
        setPassword('');
        setConfirmPassword('');
      }, 10000); // Clear after 10 seconds
      return;
    }
    if (password !== confirmPassword) {
      setMessage(<p className="error">{translations[language].matchError}</p>);
      setTimeout(() => {
        setMessage('');
        setPassword('');
        setConfirmPassword('');
      }, 3000); // Clear after 3 seconds
      return;
    }
    try {
      const response = await axios.post(`${API_URL}/change-password`, {
        username, // Use logged-in username
        newPassword: password, // Send only new password
      });
      if (response.data.success) {
        setMessage(
          <p className="success">
            {translations[language].successMessage}
            {username}!
          </p>
        );
        setTimeout(() => {
          setMessage('');
          setPassword('');
          setConfirmPassword('');
        }, 3000); // Clear after 3 seconds
      } else {
        setMessage(<p className="error">{translations[language].matchError}</p>);
        setTimeout(() => {
          setMessage('');
          setPassword('');
          setConfirmPassword('');
        }, 3000); // Clear after 3 seconds
      }
    } catch (error) {
      console.error('Password Change Error:', error);
      setMessage(<p className="error">{translations[language].matchError}</p>);
      setTimeout(() => {
        setMessage('');
        setPassword('');
        setConfirmPassword('');
      }, 3000); // Clear after 3 seconds
    }
  } else {
    setMessage(<p className="error">{translations[language].fieldsError}</p>);
    setTimeout(() => {
      setMessage('');
      setPassword('');
      setConfirmPassword('');
    }, 3000); // Clear after 3 seconds
  }
};  
  
  // Handle logout
const handleLogout = () => {
  axios
    .post(`${API_URL}/logout`)
    .then(() => {
      setLoggedIn(false);
      setUsername('');
      setMessage('');
    })
    .catch((error) => {
      console.error('Logout Error:', error);
      setMessage(<p className="error">Logout failed. Please try again.</p>);
      setTimeout(() => setMessage(''), 2000); // Clear after 2 seconds
    });
};  
  
return (
  <div className="App">
    {/* Left Container for Logo, Title, and Form */}
    <div className="left-container">
      <img src="/logo.png" alt="DragonDoson Logo" style={{ width: '170px' }} />
      <h1>{translations[language].title}</h1>
      {!loggedIn ? (
        // Login Form
        <form onSubmit={handleLogin}>
          <div>
            <label>{translations[language].loginUsernameLabel}</label>
            <input
              type="text"
              value={loginUsername}
              onChange={(e) => setLoginUsername(e.target.value)}
              placeholder={translations[language].loginPlaceholder}
            />
          </div>
          <div>
            <label>{translations[language].loginPasswordLabel}</label>
            <input
              type={showLoginPassword ? 'text' : 'password'}
              value={loginPassword}
              onChange={(e) => setLoginPassword(e.target.value)}
              placeholder={translations[language].passwordPlaceholder}
            />
            <button
              type="button"
              className="show-password"
              onClick={() => setShowLoginPassword(!showLoginPassword)}
            >
              {showLoginPassword ? '👁️‍🗨️' : '👁️'}
            </button>
          </div>
          <button type="submit">{translations[language].loginButton}</button>
          <p>{loginMessage}</p>
        </form>
      ) : (
        // Password Change Form
        <form onSubmit={handleSubmit}>
          <p className="welcome">
            {translations[language].welcome}
            {username}!
          </p>
          <div>
            <label>{translations[language].usernameLabel}</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder={translations[language].loginPlaceholder}
              disabled
            />
          </div>
          <div>
            <label>{translations[language].newPasswordLabel}</label>
            <input
              type={showNewPassword ? 'text' : 'password'}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder={translations[language].newPasswordPlaceholder}
            />
            <button
              type="button"
              className="show-password"
              onClick={() => setShowNewPassword(!showNewPassword)}
            >
              {showNewPassword ? '👁️‍🗨️' : '👁️'}
            </button>
          </div>
          <div>
            <label>{translations[language].confirmLabel}</label>
            <input
              type={showConfirmPassword ? 'text' : 'password'}
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              placeholder={translations[language].confirmPlaceholder}
            />
            <button
              type="button"
              className="show-password"
              onClick={() => setShowConfirmPassword(!showConfirmPassword)}
            >
              {showConfirmPassword ? '👁️‍🗨️' : '👁️'}
            </button>
          </div>
          <button type="submit">{translations[language].changePasswordButton}</button>
          <p>{message}</p>
        </form>
      )}
    </div>

    {/* Right Container for Buttons */}
    <div className="top-buttons">
      <button
        className="language-toggle"
        onClick={() => setLanguage(language === 'en' ? 'vi' : 'en')}
      >
        {language === 'en' ? 'Tiếng Việt' : 'English'}
      </button>
      {loggedIn && (
        <button onClick={handleLogout} className="logout">
          {translations[language].logoutButton}
        </button>
      )}
    </div>
  </div>
);
}

export default App;

