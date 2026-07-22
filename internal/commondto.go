package internal

func (r *AuthRepository) GetRoles() ([]string, error) {

	rows, err := r.DB.Query(
		"SELECT * FROM " + dbcfg.AuthSchema + ".auth_getroles()",
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
