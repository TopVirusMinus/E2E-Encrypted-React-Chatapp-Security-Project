import axios from "axios";
import { useState } from "react";

const TheirMessage = ({ lastMessage, message }) => {
  const [encryptedMesssage, setEncryptedMesssage] = useState(message.text);

  const isFirstMessageByUser =
    !lastMessage || lastMessage.sender.username !== message.sender.username;

  const decryptionEndpoints = {
    caesar: "caesar_decrypt",
    aes: "aes_decrypt",
    rsa: "rsa_decrypt",
    des: "des_decrypt",
    gamal: "gamal_decrypt",
    rc4: "rc4_decrypt",
  };

  const handleDecryption = async () => {
    const algorithm = encryptedMesssage.split("/").pop();
    console.log("decryption algorithm", algorithm);

    const cleanedEncryptedMesssage =
      encryptedMesssage.lastIndexOf("/") > -1
        ? encryptedMesssage.substring(0, encryptedMesssage.lastIndexOf("/"))
        : encryptedMesssage;

    console.log("cleanedEncryptedMesssage", cleanedEncryptedMesssage);

    try {
      const response = await axios.post(
        `http://localhost:5000/${decryptionEndpoints[algorithm]}`,
        { encryptedMesssage: cleanedEncryptedMesssage }
      );
      setEncryptedMesssage(response.data.decrypted_message);
    } catch (error) {
      console.error("Error sending POST request:", error);
    }
  };

  return (
    <div className="message-row">
      {isFirstMessageByUser && (
        <div
          className="message-avatar"
          style={{
            backgroundImage: message.sender && `url(${message.sender.avatar})`,
          }}
        />
      )}
      <div
        className="message"
        style={{
          float: "left",
          backgroundColor: "#CABCDC",
          marginLeft: isFirstMessageByUser ? "4px" : "48px",
        }}
      >
        {encryptedMesssage}
      </div>
      <a
        onClick={() => handleDecryption()}
        style={{
          textDecoration: "underline",
          cursor: "pointer",
          textAlign: "center",
          padding: "10px",
        }}
      >
        Decrypt
      </a>
    </div>
  );
};

export default TheirMessage;
