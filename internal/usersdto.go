package internal

import (
	"context"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type UserMapDTO struct {
	Username string
}

func (r *AuthRepository) UserMap(

	ctx context.Context,
	dto UserMapDTO,

) (int64, error) {

	var userID int64

	query := `
			CALL ` + dbcfg.AuthSchema + `.auth_user_map(
	            $1,
	            $2
	        )
		`

	err := r.DB.QueryRowContext(
		ctx,
		query,
		dto.Username,
		&userID,
	).Scan(&userID)

	if err != nil {
		return 0, err
	}

	return userID, nil
}

type ChangePasswordDTO struct {
	UserID         int64
	HashedPassword string
}

func (r *AuthRepository) ChangePassword(
	ctx context.Context,
	dto ChangePasswordDTO,
) error {

	query := `
        CALL ` + dbcfg.AuthSchema + `.auth_user_changepassword(
            $1,
            $2
        )
    `

	_, err := r.DB.ExecContext(
		ctx,
		query,
		dto.UserID,
		dto.HashedPassword,
	)

	return err
}

func (r *AuthRepository) GetUserRoles(
	userid int64,
) ([]string, error) {

	rows, err := r.DB.Query(
		"SELECT * FROM "+dbcfg.AuthSchema+".auth_getuserroles($1)",
		userid,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ret []string

	for rows.Next() {
		var role string

		if err := rows.Scan(&role); err != nil {
			return nil, err
		}

		ret = append(ret, role)
	}

	return ret, nil
}
