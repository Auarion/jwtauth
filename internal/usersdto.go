package internal

import (
	"context"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type UserMapDTO struct {
	Username string
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

		if rows.Err() != nil {
			return nil, err
		}

		var role string
		var roleid int32

		if err := rows.Scan(&role, &roleid); err != nil {
			return nil, err
		}

		ret = append(ret, role)
	}

	return ret, nil
}

func (r *AuthRepository) GetUserRolesByUsername(
	username string,
) ([]string, error) {

	rows, err := r.DB.Query(
		"SELECT * FROM "+dbcfg.AuthSchema+".auth_getuserroles_byusername($1)",
		username,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ret []string

	for rows.Next() {

		if rows.Err() != nil {
			return nil, err
		}

		var role string
		var roleid int32

		if err := rows.Scan(&role, &roleid); err != nil {
			return nil, err
		}

		ret = append(ret, role)
	}

	return ret, nil
}
