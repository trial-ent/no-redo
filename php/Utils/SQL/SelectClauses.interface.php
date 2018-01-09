<?php
/**
 * Description of SelectClauses
 *
 * Created on 04/09/2016, ~22:26:45
 * @author Matheus Leonardo dos Santos Martins
 * @copyright (c) 2016, TRIAL
 * 
 * @package SQLUtils
 * 
 * 25/09/2016, 00:52: added returnFoundRows()
 */

/*
 * 21/01/2017
 *      19:40:49 => added namespace NoRedo\Utils\SQL
 */

namespace NoRedo\Utils\SQL;

interface SelectClauses {
    
    /**
     * 
     * 
     * @param array|string $group_by 
     * @return \Select
     */
    public function groupBy($group_by);
    
    /**
     * 
     * 
     * @param array|string $inner_join 
     * @return \Select
     */
    public function innerJoin($inner_join);
    
    /**
     * 
     * 
     * @param array|string $left_join 
     * @return \Select
     */
    public function leftJoin($left_join);
    
    /**
     * 
     * 
     * @param string $limit 
     * @return \Select
     */
    public function limit($limit);
    
    /**
     * 
     * 
     * @param array|string $order_by 
     * @return \Select
     */
    public function orderBy($order_by);
    
    /**
     * 
     * 
     * @param bool $count 
     * @return \Select
     */
    public function countFoundRows(bool $count);
    
    /**
     * 
     * 
     * @param array|string $right_join 
     * @return \Select
     */
    public function rightJoin($right_join);
    
    /**
     * 
     * 
     * @param string $where 
     * @return \Select
     */
    public function where($where);
    
    /**
     * Added on: 06/09/2016, 18:23:29
     * 
     * @param int $mode
     * @param mixed $object
     * @param array $construct
     * @return \Select
     */
    public function fetchMode($mode, $object = null, $construct = null);
    
}
