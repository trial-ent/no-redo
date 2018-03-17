<?php
/**
 * Description of FixItAccount
 * 
 * ConnectDB adapted to new version on 08/09/2016, ~20:47:28
 * 
 * Created on 05/09/2016, ~16:11:40
 * @copyright (c) 2016, TRIAL
 * @author Matheus Leonardo dos Santos Martins
 * 
 * @version 1.1
 * @package Account
 */

/*
 * Implementation of RG, CPF, Escolaridade, Ocupação principal started on 05/09/2016, ~16:32:00
 * 
 * 22/11/2016, 18:28:20 - 18:44:53 => updated all codes to new codes, fixed authenticateUser() not making login right
 * 
 * 24/12/2016, 14:51:52 => update ConnectDB code to DB code; added use Query, Select statement
 * 
 * 15/03/2017, 12:29:15 => added namespace NoRedo\TRIAL\Account;
 * 
 * 13/03/2018
 *      16:36:19 = added getFranchise()
 *      16:40:28 = modified get() to adapt to new franchise code
 *      16:41:55 = added const FRANCHISE, private $franchise
 *      16:43:12 = added hasFranchise()
 */

namespace NoRedo\TRIAL\Account;

use \PDO, \DateTime,
        NoRedo\TRIAL\Account as TRIALAccount, NoRedo\Utils\Database, NoRedo\Utils\SQL\Query, NoRedo\Utils\SQL\Select, NoRedo\Utils\SQL\Insert, NoRedo\Utils\Message;

class FixIt implements \JsonSerializable {
    
    const TABLE_CITIZENS = 'users';
    const TABLE_GOVERNMENTS = 'governments';
    
    const ID = 'id';
    const USER = 'user';
    const ACCOUNT_TYPE = 'type';
    const LEVEL = 'level';
    const XP = 'experience';
    const FRANCHISE_ID = 'franchise_id';
    const SIGNED_ON = 'register_date_time';
    
    private static $con;
    
    private $id = 0;
    private $user = 0;
    private $type;
    private $level = 1;
    private $experience = 0;
    private $franchise;
    private $register_date_time;
    
    private function __construct(array $copy = null) {
        $loop = $copy ?? $this;
        foreach ($loop as $key => $value) {
            if ($key === self::ACCOUNT_TYPE)
                continue;
            if ($key === self::USER && (is_int($value) || is_string($value)))
                $value = $this->type === TRIALAccount::USER ? User::get((int) $value) : Government::get((int) $value);
            $this->{$key} = $value;
        }
        unset($this->type);
    }
    
    /**
     * Gets the Database connection. This creates a new connection if hasn't estabilished yet.
     * 
     * @return PDO Estabilished connection
     * @since 1.03
     */
    private static function con() : PDO {
        if (!self::$con) {
            self::$con = Database::connect(DATABASE_FIX_IT);
        }
        return self::$con;
    }
    
    /**
     * @return FixIt
     * @since 1.03
     */
    public static function copy(array $copy) : FixIt {
        return new self($copy);
    }
    
    /**
     * @param TRIALAccount $account
     * @return type
     * @since 1.0
     */
    public static function authenticate(int $id, string $type = TRIALAccount::USER) {
        $profile = self::get($id, $type);
        if (!$profile) {
            $profile = self::create($id, $type);
        }
        $domain = filter_input(INPUT_SERVER, 'HTTP_HOST') !== 'localhost' ? '.trialent.com' : 'localhost';
        setcookie('trl_fi', $profile->getId(), time() + (60 * 60 * 24 * 365), '/', $domain);
        return [self::ID => $profile->getId(), self::LEVEL => $profile->getLevel(), self::XP => $profile->getXP(), 'message' => Message::EXIST];
    }
    
    /**
     * 
     * @param int $id
     * @param string $type
     * @return type
     * @since 1.0
     */
    public static function get(int $id, string $type = TRIALAccount::USER)  {
        return Query::helper((new Select(self::con()))->table(($type === TRIALAccount::USER ? self::TABLE_CITIZENS : self::TABLE_GOVERNMENTS) . ' AS a')->columns($type === TRIALAccount::USER ? ['a.' . self::ID, 'a.' . self::USER, 'a.' . self::LEVEL, 'a.' . self::XP, 'c.place_id AS ' . self::FRANCHISE_ID, '\'' . $type . '\' AS ' . self::ACCOUNT_TYPE]: ['a.' . self::ID, 'a.' . self::USER])->leftJoin(['cities AS c ON a.franchise_owner = a.id'])->where('a.' . self::USER . ' = :user')->values([':user' => $id])->fetchMode(PDO::FETCH_CLASS, self::class)->run(), function ($query) {
            if ($query->existRows()) {
                return $query->getResult()[0];
            }
            return null;
        });
    }
    
    /**
     * 
     * @param TRIALAccount $account
     * @return type
     * @since 1.03
     */
    public static function create(int $id, string $type = TRIALAccount::USER) {
        return Query::helper((new Insert(self::con()))->table($type === TRIALAccount::USER ? self::TABLE_CITIZENS : self::TABLE_GOVERNMENTS)->columns([self::USER, self::SIGNED_ON])->values([$id, $signed_on = date('Y-m-d H:i:s')])->run(), function ($query) use ($id, $type, $signed_on) {
            return FixIt::copy([self::ID => $query->getResult()['id'], self::USER => $id, self::ACCOUNT_TYPE => $type, self::LEVEL => 1, self::XP => 0, self::SIGNED_ON => $signed_on]);
        });
    }
    
    /**
     * @return int Account ID
     * @since 1.03
     */
    public function getId() {
        return $this->id;
    }
    
    /**
     * @return TRIALAccount Account user
     * @since 1.03
     */
    public function getUser() : TRIALAccount {
        return $this->user;
    }
    
    /**
     * @return int Citizen level
     * @since 1.03
     */
    public function getLevel() : int {
        return $this->level;
    }
    
    /**
     * @return int Citizen XP
     * @since 1.03
     */
    public function getXP() : int {
        return $this->experience;
    }
    
    /**
     * @return int Citizen franchise's Place ID
     * @since 1.1
     */
    public function getFranchiseId() {
        return $this->franchise;
    }
    
    /**
     * @return bool if Citizen has a franchise
     * @since 1.1
     */
    public function hasFranchise(): bool {
        return is_string($this->getFranchiseId());
    }
    
    /**
     * @return DateTime Citizen signed on
     * @since 1.03
     */
    public function getSignedOn() : DateTime {
        return new DateTime($this->register_date_time);
    }

    public function jsonSerialize() {
        return [self::ID => $this->id, self::XP => $this->experience, self::LEVEL => $this->level];
    }

}