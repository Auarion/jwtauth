package internal

func (r *AuthRepository) GetRoles() (map[string]int, error) {

	rows, err := r.DB.Query(
		"SELECT * FROM " + dbcfg.AuthSchema + ".auth_getroles()",
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ret map[string]int = make(map[string]int)

	for rows.Next() {
		var role string
		var roleid int

		if err := rows.Scan(&role, &roleid); err != nil {
			return nil, err
		}

		ret[role] = roleid
	}

	return ret, nil
}
