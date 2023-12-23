import { useState } from "react";
import { SendOutlined } from "@ant-design/icons";
import { sendMessage, isTyping } from "react-chat-engine";
import axios from "axios";

const MessageForm = (props) => {
  const [value, setValue] = useState("");
  const { chatId, creds } = props;
  const [selectedAlgorithm, setSelectedAlgorithm] = useState("");
  const encryptionAlgorithms = ["Caesar", "AES", "RSA", "DES", "Gamal", "RC4"];

  const encryptionEndpoints = {
    Caesar: "caesar_encrypt",
    AES: "aes_encrypt",
    RSA: "rsa_encrypt",
    DES: "des_encrypt",
    Gamal: "gamal_encrypt",
    RC4: "rc4_encrypt",
  };

  const handleDropdownChange = (e) => {
    setSelectedAlgorithm(e.target.value);
  };

  const handleChange = (event) => {
    setValue(event.target.value);

    isTyping(props, chatId);
  };

  const handleSubmit = (event) => {
    event.preventDefault();

    const text = value.trim();

    if (text.length > 0) {
      sendMessage(creds, chatId, { text });
    }

    setValue("");
  };

  const handleEncryption = async () => {
    try {
      const response = await axios.post(
        `http://localhost:5000/${encryptionEndpoints[selectedAlgorithm]}`,
        { chat_id: chatId, value }
      );
      setValue(response.data.encrypted_message);
    } catch (error) {
      console.error("Error sending POST request:", error);
    }
  };

  return (
    <form className="message-form" onSubmit={handleSubmit}>
      <input
        className="message-input"
        placeholder="Send a message..."
        value={value}
        onChange={handleChange}
        onSubmit={handleSubmit}
      />

      <button type="submit" className="send-button">
        <SendOutlined className="send-icon" />
      </button>
      <div>
        <select value={selectedAlgorithm} onChange={handleDropdownChange}>
          <option value="">Select an algorithm</option>
          {encryptionAlgorithms.map((algorithm, index) => (
            <option key={index} value={algorithm}>
              {algorithm}
            </option>
          ))}
        </select>
        <button
          onClick={(e) => {
            e.preventDefault();
            handleEncryption();
            console.log(`encrypting using ${selectedAlgorithm}`);
          }}
        >
          Encrypt
        </button>
        <button
          style={{ display: "flex" }}
          onClick={() => {
            localStorage.clear();
            window.location.reload();
          }}
        >
          Log Out
        </button>
      </div>
    </form>
  );
};

export default MessageForm;
