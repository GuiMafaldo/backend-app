const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();

const port = 3000;

app.use(cors());
app.use(express.json());

const users = []


app.post('/register', (req, res) => {
    const { name, email, password } = req.body;

    // Validação básica
    if (!name || !email || !password) {
        return res.status(400).json({ error: 'Todos os campos são obrigatórios.' });
    }

    // Verificar se o e-mail já está em uso
    const existingUser = users.find(user => user.email === email);
    if (existingUser) {
        return res.status(409).json({ error: 'E-mail já registrado.' });
    }

    // Criptografar a senha
    const hashedPassword = bcrypt.hashSync(password, 10);

    // Adicionar o novo usuário
    const newUser = { name, email, password: hashedPassword };
    users.push(newUser);

    // Retornar o usuário registrado (sem a senha)
    res.status(201).json({ message: 'Registrado com sucesso!', user: { name, email } });
});

// Retornar todos os usuários
app.get('/users', (req,res) => {
    res.json(users)
})

app.post('/login', async (req, res) => {

    try {
    const { email, password } = req.body;
    const user = users.find(user => user.email === email);

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