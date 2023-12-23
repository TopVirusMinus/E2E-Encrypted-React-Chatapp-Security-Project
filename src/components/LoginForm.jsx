import { useState } from 'react';
import axios from 'axios';

const projectID = 'f0a9e0f1-628e-4e4a-ad54-97bb6b1e4f28';
const privateKey = '0e2058bc-b67c-49f3-92ff-d5841e0377e7';

const LoginForm = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [register, setRegister] = useState(false);

  const handleLogin = async (e) => {
    e.preventDefault();

    const authObject = { 'Project-ID': projectID, 'User-Name': username, 'User-Secret': password };

    try {
      await axios.get('https://api.chatengine.io/chats', { headers: authObject });

      localStorage.setItem('username', username);
      localStorage.setItem('password', password);

      window.location.reload();
      setError('');
    } catch (err) {
      setError('Oops, incorrect credentials.');
    }
  };

  const handleRegister = async (e) => {
    e.preventDefault();

    const authObject = {'Private-Key': privateKey}
    
    try {
        await axios.post(
            "https://api.chatengine.io/users/",
            {'username': username, 'secret': password},
            {'headers': authObject} 
          )
          .then(r => console.log(r))

          localStorage.setItem('username', username)
        localStorage.setItem('password', password)

        window.location.reload()
     } catch (error) {
         console.log(error)
         setError('Incorrect credentials, try again')
     }
                        
}

  if(!register){
    return (
        <div className="wrapper">
        <div className="form">
            <h1 className="title">Login Secure Chat App</h1>
            <form onSubmit={handleLogin}>
            <input type="text" value={username} onChange={(e) => setUsername(e.target.value)} className="input" placeholder="Username" required />
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} className="input" placeholder="Password" required />
            <div style={{"textAlign":"center"}}>
                <button type="submit" className="button">
                <span>Start chatting</span>
                </button>
            </div>
            </form>
            <a onClick={()=> setRegister(true)} style={{'textDecoration': 'underline', 'cursor':'pointer'}}>No account? Register here</a>
            <h1>{error}</h1>
            
        </div>
        </div>

    );
  }
  return (
    <div className="wrapper">
    <div className="form">
        <h1 className="title">Register to Secure Chat App</h1>
        <form onSubmit={handleRegister}>
        <input type="text" value={username} onChange={(e) => setUsername(e.target.value)} className="input" placeholder="Username" required />
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} className="input" placeholder="Password" required />
        <div style={{"textAlign":"center"}}>
            <button type="submit" className="button">
            <span>Start chatting</span>
            </button>
        </div>
        </form>
        {register && <a onClick={()=> setRegister(false)} style={{'textDecoration': 'underline', 'cursor':'pointer'}}>Have an account? Login here</a>}
        <h1>{error}</h1>
    </div>
    </div>

);
};

export default LoginForm;