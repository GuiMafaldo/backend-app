const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const pool = require('./service/database')

const app = express();

const port = 3000;

app.use(cors());
app.use(express.json());

// REGISTAR USUARIOS NO BANCO DE DADOS
app.post('/register', async (req, res) => {
    const { name, email, password } = req.body;

    // Validação básica
    if (!name || !email || !password) {
        return res.status(400).json({ error: 'Todos os campos são obrigatórios.' });
    }

    // Verificar se o e-mail já está em uso
    const existingUser = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
    if (existingUser.rows.length > 0) {
        return res.status(409).json({ error: 'E-mail já registrado.' });
    }

    // Criptografar a senha
    const hashedPassword = await bcrypt.hash(password, 10);

    // Adicionar o novo usuário
    await pool.query('INSERT INTO usuarios (name, email, password) VALUES ($1,$2,$3)',[name, email, hashedPassword])

    // Retornar o usuário registrado (sem a senha)
    res.status(201).json({ message: 'Registrado com sucesso!', user: { name, email } });
});

// RETORNA TODOS OS USUARIOS CADASTRADOS
app.get('/users', async(req,res) => {
    const result = await pool.query('SELECT name, email FROM usuarios')
    res.json(result.rows)
})

//EXECUTAR A VERIFICAÇÃO E LOGAR NO APP
app.post('/login', async (req, res) => {
    try {
    const { email, password } = req.body;
    const userResult = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email])
    const user = userResult.rows[0]

    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(403).json({ error: 'Credentials are incorrect' });
    }

    // Certifique-se de que `jwt.sign` está correto
    const token = jwt.sign({ email }, 'secreto', { expiresIn: '1h' });
    res.json({ token });
}catch(err){
    console.error(err, 'Um erro ocorreu ao tentar fazer login');
}
});


app.get('/protected', (req, res) =>{
    const authHeader = req.headers.authorization;

    if(!authHeader) return res.sendStatus(401);

    const token = authHeader.split(' ')[1];
    jwt.verify(token, 'secreto', (err, user) => {
        if(err) return res.sendStatus(403)
        res.json({ message: 'Acess granted', user});
    })
})

app.listen(port, () => {
    console.log(`Server is running on port ${port}`)
})