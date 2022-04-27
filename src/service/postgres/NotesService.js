const { Pool } = require('pg')
const { nanoid } = require('nanoid');
const NotFoundError = require('../../exception/NotFoundError');
const InvariantError = require('../../exception/InvariantError');
const AuthorizationError = require('../../exception/AuthorizationError ');

class NotesService {
    constructor(collaborationService) {
        this._pool = new Pool()
        this._collaborationService = collaborationService
    }

    async addNote({ title, body, tags, owner }) {
        const id = nanoid(16)
        const createdAt = new Date().toISOString()
        const updatedAt = createdAt

        const query = {
            text: 'INSERT INTO notes VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id',
            values: [ id, title, body, tags, createdAt, updatedAt, owner ]
        }

        const result = await this._pool.query(query)
        if (!result.rows[ 0 ].id) {
            throw new InvariantError('Catatan gagal ditambahkan')
        }

        return result.rows[ 0 ].id
    }

    async getNotes(owner) {
        const query = {
            text: 'SELECT * FROM notes WHERE owner = $1',
            values: [ owner ],
        };
        const result = await this._pool.query(query);
        return result.rows;
    }

    async getNoteById(id) {
        const query = {
            text: 'SELECT * FROM notes WHERE id = $1',
            values: [ id ],
        }
        const result = await this._pool.query(query)
        if (!result.rows.length) {
            throw new NotFoundError('Catatan tidak ditemukan')
        }
        return result.rows[ 0 ]

    }

    async editNoteById(id, { title, body, tags }) {
        const updatedAt = new Date().toISOString()
        const query = {
            text: 'UPDATE notes SET title = $1, body = $2, tags = $3  WHERE id = $4 RETURNING id',
            values: [ title, body, tags, id ],
        }
        const result = await this._pool.query(query)

        if (!result.rows.length) {
            throw new NotFoundError('Gagal memperbarui catatan. Id tidak ditemukan')
        }

    }

    async deleteNoteById(id) {
        const query = {
            text: 'DELETE FROM notes WHERE id = $1 RETURNING id',
            values: [ id ],
        };

        const result = await this._pool.query(query);
        if (!result.rows.length) {
            throw new NotFoundError('Catatan gagal dihapus. Id tidak ditemukan')
        }
    }

    async verifyNoteOwner(id, owner) {
        const query = {
            text: 'SELECT * FROM notes WHERE id = $1',
            values: [ id ],
        };
        const result = await this._pool.query(query);
        if (!result.rows.length) {
            throw new NotFoundError('Catatan tidak ditemukan');
        }

        const note = result.rows[ 0 ];
        if (note.owner !== owner) {
            throw new AuthorizationError('Anda tidak berhak mengakses resource ini');
        }
    }

    async verifyNoteAccess(noteId, userId) {
        try {
            await this.verifyNoteOwner(noteId, userId);
        } catch (error) {
            console.log("🚀4life -> file: NotesService.js -> line 100 -> NotesService -> verifyNoteAccess -> error -> ", { error });
            if (error instanceof NotFoundError) {
                throw error;
            }

            try {
                await this._collaborationService.verifyCollaborator(noteId, userId);
            } catch (error) {
                throw error;
            }
        }

    }
}

module.exports = NotesService