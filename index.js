require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcrypt'); // bcrypt 추가

const app = express();
const PORT = 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());

// MySQL 데이터베이스 연결
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
});

// 데이터베이스 연결 확인
db.connect(err => {
    if (err) {
        console.error('Database connection failed:', err);
        return;
    }
    console.log('Connected to the database.');
});

// 회원가입 API
app.post('/signup', (req, res) => {
    const { username, phone, password } = req.body;

    // 비밀번호 암호화
    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) {
            console.error('Error encrypting password:', err);
            return res.status(500).send('Error encrypting password.');
        }

        // 암호화된 비밀번호를 DB에 저장
        const query = 'INSERT INTO users (username, phone, password) VALUES (?, ?, ?)';
        db.query(query, [username, phone, hashedPassword], (err, result) => {
            if (err) {
                console.error('Error signing up:', err);
                res.status(500).send('Error signing up.');
                return;
            }
            res.status(200).send('User registered successfully.');
        });
    });
});

// 로그인 API
app.post('/login', (req, res) => {
    const { phone, password } = req.body;

    // 전화번호로 사용자를 찾기
    const query = 'SELECT * FROM users WHERE phone = ?';
    db.query(query, [phone], (err, results) => {
        if (err) {
            console.error('Error logging in:', err);
            res.status(500).send('Error logging in.');
            return;
        }

        if (results.length > 0) {
            // 암호화된 비밀번호와 사용자가 입력한 비밀번호 비교
            bcrypt.compare(password, results[0].password, (err, isMatch) => {
                if (err) {
                    console.error('Error comparing passwords:', err);
                    res.status(500).send('Error comparing passwords.');
                    return;
                }

                if (isMatch) {
                    // 로그인 성공: username 반환
                    res.status(200).json({
                        message: 'Login successful',
                        username: results[0].username,
                    });
                } else {
                    res.status(401).send('Invalid credentials.');
                }
            });
        } else {
            res.status(401).send('Invalid credentials.');
        }
    });
});

// 서버 실행
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});