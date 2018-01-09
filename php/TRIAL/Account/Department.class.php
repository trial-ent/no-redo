<?php
/**
 * Description of Department
 *
 * Created on 24/12/2016, 17:20:53
 * @author Matheus Leonardo dos Santos Martins
 * @copyright (c) 2016, TRIAL
 * 
 * @version 1.0
 * @package Account
 */

/*
 * 21/01/2017, 20:39:44 => added namespace NoRedo\TRIAL\Account
 */

namespace NoRedo\TRIAL\Account;

use NoRedo\TRIAL\Account as TRIALAccount, NoRedo\Utils\SQL\Select, NoRedo\Utils\Request;

class Department extends TRIALAccount {
    
    private $government_id;
    private $name;
    private $login;
    
    public function __construct($search = null, array $columns = null) {
        parent::__construct(TRIALAccount::GOVERNMENTAL_DEPARTMENT);
        if ($columns == null) {
            $columns = 'id, government AS government_id, photo, name, login, password, activated';
        } else {
            $columns = implode(', ', $columns);
        }
        $type = gettype($search);
        $con = Database::connect(DATABASE_USERS);
        switch ($type) {
            case 'string':
                $data = (new Select($con))->table('governmental_departments')->columns($columns)->where('login = :login')->values([':login' => $search])->run();
                break;
            case 'integer':
                $data = (new Select($con))->table('governmental_departments')->columns($columns)->where('id = :id')->values([':id' => $search])->run();
                break;
            default:
                $data = $search != null ? $search : [];
        }
        if (gettype($data) === 'object') {
            if ($data->success() && $data->existRows()) {
                $data = $data->getResult()[0];
            }
        }
        foreach ($data as $key => $value) {
            $this->{$key} = $value;
        }
    }
    
    public function getGovernmentId() {
        return $this->government_id;
    }
    
    public function getName() {
        return $this->name;
    }
    
    public function getLogin() {
        return $this->login;
    }
    
}
